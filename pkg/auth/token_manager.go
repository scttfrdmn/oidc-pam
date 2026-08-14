package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
)

// TokenManager handles token lifecycle management
type TokenManager struct {
	tokenStore *TokenStore
	encryption *security.Encryption
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// TokenStore represents a token storage backend
type TokenStore struct {
	tokens           map[string]*StoredToken
	fingerprintIndex map[string]string // fingerprint → tokenID for O(1) ValidateToken
	mutex            sync.RWMutex
}

// StoredToken represents a token stored in the token store
type StoredToken struct {
	ID           string
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresAt    time.Time
	UserID       string
	SessionID    string
	Fingerprint  string
	Encrypted    bool
	Metadata     map[string]interface{}
	CreatedAt    time.Time
	LastUsed     time.Time
}

// The three encrypted fields of a stored token. They are named in the additional
// authenticated data so that a ciphertext cannot be moved between fields of the
// same record either: an access token pasted into the refresh_token slot would
// otherwise decrypt, and the broker would present it to the provider as a refresh
// token.
const (
	tokenFieldAccess  = "access_token"
	tokenFieldRefresh = "refresh_token"
	tokenFieldID      = "id_token"
)

// tokenAADVersion prefixes every AAD so a future change to what is bound can be
// told from this one rather than silently producing ciphertexts that will not
// open. There is nothing to migrate today — the token store is an in-memory map
// that lives and dies with the process, so no ciphertext ever outlives the code
// that wrote it — which is why the record format needs no version field of its
// own. If the store is ever persisted, that stops being true and this constant is
// where the compatibility break becomes visible.
const tokenAADVersion = "oidc-pam/stored-token/v1"

// tokenAAD returns the additional authenticated data binding one encrypted field
// of a stored token to the identity it was stored for (#232).
//
// AES-GCM already proves a ciphertext was not modified, but it says nothing about
// where the ciphertext belongs: without AAD, a refresh token lifted out of user
// A's record and written into user B's decrypts cleanly, the tag validates, and
// the broker then refreshes A's credentials while every downstream decision —
// policy, audit attribution, key provisioning — is made for B. With the record's
// user, session and field name bound in, such a ciphertext fails to open.
//
// The parts are length-prefixed rather than joined by a separator, so no
// combination of user and session IDs can produce the same AAD as a different
// pair.
func tokenAAD(field, userID, sessionID string) []byte {
	var b strings.Builder
	b.WriteString(tokenAADVersion)
	for _, part := range []string{field, userID, sessionID} {
		fmt.Fprintf(&b, "|%d:%s", len(part), part)
	}
	return []byte(b.String())
}

// NewTokenManager creates a new token manager
func NewTokenManager(cfg *config.Config) (*TokenManager, error) {
	// Initialize encryption (always required)
	encryption, err := security.NewEncryption(cfg.Security.TokenEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token encryption: %w", err)
	}

	// Initialize token store
	tokenStore := &TokenStore{
		tokens:           make(map[string]*StoredToken),
		fingerprintIndex: make(map[string]string),
	}

	return &TokenManager{
		tokenStore: tokenStore,
		encryption: encryption,
		stopChan:   make(chan struct{}),
	}, nil
}

// Start starts the token manager
func (tm *TokenManager) Start(ctx context.Context) error {
	log.Info().Msg("Starting token manager")

	// Start cleanup goroutine
	tm.wg.Add(1)
	go tm.cleanupExpiredTokens(ctx)

	return nil
}

// Stop stops the token manager
func (tm *TokenManager) Stop() error {
	log.Info().Msg("Stopping token manager")

	close(tm.stopChan)
	tm.wg.Wait()

	return nil
}

// StoreToken encrypts a token and stores it, returning the ID the caller should
// keep. Callers hold the ID rather than the token: the returned ID is a lookup
// key with no value on its own, whereas an access or refresh token in a
// long-lived struct is a usable credential.
func (tm *TokenManager) StoreToken(token *Token, userID, sessionID string) (string, error) {
	// Generate token ID
	tokenID, err := tm.generateTokenID()
	if err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Encrypt token if encryption is enabled
	accessToken := token.AccessToken
	refreshToken := token.RefreshToken
	idToken := token.IDToken
	encrypted := false

	if tm.encryption != nil {
		var err error
		// Each field is bound to the account and session it is being stored for,
		// so the ciphertext is only usable in this record (#232).
		accessToken, err = tm.encryption.EncryptWithAAD(token.AccessToken, tokenAAD(tokenFieldAccess, userID, sessionID))
		if err != nil {
			return "", fmt.Errorf("failed to encrypt access token: %w", err)
		}

		if token.RefreshToken != "" {
			refreshToken, err = tm.encryption.EncryptWithAAD(token.RefreshToken, tokenAAD(tokenFieldRefresh, userID, sessionID))
			if err != nil {
				return "", fmt.Errorf("failed to encrypt refresh token: %w", err)
			}
		}

		if token.IDToken != "" {
			idToken, err = tm.encryption.EncryptWithAAD(token.IDToken, tokenAAD(tokenFieldID, userID, sessionID))
			if err != nil {
				return "", fmt.Errorf("failed to encrypt ID token: %w", err)
			}
		}

		encrypted = true
	}

	// Create stored token
	storedToken := &StoredToken{
		ID:           tokenID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		ExpiresAt:    token.ExpiresAt,
		UserID:       userID,
		SessionID:    sessionID,
		Fingerprint:  token.Fingerprint,
		Encrypted:    encrypted,
		Metadata:     make(map[string]interface{}),
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
	}

	// Store token claims in metadata
	if token.Claims != nil {
		storedToken.Metadata["claims"] = token.Claims
	}

	// Store in token store and update fingerprint index
	tm.tokenStore.mutex.Lock()
	tm.tokenStore.tokens[tokenID] = storedToken
	if storedToken.Fingerprint != "" {
		tm.tokenStore.fingerprintIndex[storedToken.Fingerprint] = tokenID
	}
	tm.tokenStore.mutex.Unlock()

	log.Debug().
		Str("token_id", tokenID).
		Str("user_id", userID).
		Str("session_id", sessionID).
		Time("expires_at", token.ExpiresAt).
		Bool("encrypted", encrypted).
		Msg("Token stored")

	return tokenID, nil
}

// GetToken retrieves a token from the token store
func (tm *TokenManager) GetToken(tokenID string) (*Token, error) {
	tm.tokenStore.mutex.RLock()
	storedToken, exists := tm.tokenStore.tokens[tokenID]
	tm.tokenStore.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("token not found")
	}

	// Check if token has expired
	if storedToken.ExpiresAt.Before(time.Now()) {
		// Remove expired token
		tm.removeToken(tokenID)
		return nil, fmt.Errorf("token expired")
	}

	// Decrypt token if needed
	accessToken := storedToken.AccessToken
	refreshToken := storedToken.RefreshToken
	idToken := storedToken.IDToken

	if storedToken.Encrypted && tm.encryption != nil {
		var err error
		// The AAD comes from the record being read, so a ciphertext that was
		// written for a different account, session or field does not open here
		// (#232).
		user, session := storedToken.UserID, storedToken.SessionID
		accessToken, err = tm.encryption.DecryptWithAAD(storedToken.AccessToken, tokenAAD(tokenFieldAccess, user, session))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt access token: %w", err)
		}

		if storedToken.RefreshToken != "" {
			refreshToken, err = tm.encryption.DecryptWithAAD(storedToken.RefreshToken, tokenAAD(tokenFieldRefresh, user, session))
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
			}
		}

		if storedToken.IDToken != "" {
			idToken, err = tm.encryption.DecryptWithAAD(storedToken.IDToken, tokenAAD(tokenFieldID, user, session))
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt ID token: %w", err)
			}
		}
	}

	// Create token
	token := &Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		TokenType:    "Bearer",
		ExpiresAt:    storedToken.ExpiresAt,
		Fingerprint:  storedToken.Fingerprint,
	}

	// Extract claims from metadata
	if claims, ok := storedToken.Metadata["claims"].(map[string]interface{}); ok {
		token.Claims = claims
	}

	// Update last used time
	tm.tokenStore.mutex.Lock()
	storedToken.LastUsed = time.Now()
	tm.tokenStore.mutex.Unlock()

	log.Debug().
		Str("token_id", tokenID).
		Str("user_id", storedToken.UserID).
		Str("session_id", storedToken.SessionID).
		Msg("Token retrieved")

	return token, nil
}

// ValidateToken validates a token fingerprint and verifies it belongs to the given user.
// Both fingerprint and userID must match to prevent token hijacking across users.
// Uses the O(1) fingerprint index for lookup.
func (tm *TokenManager) ValidateToken(tokenFingerprint, userID string) (*StoredToken, error) {
	tm.tokenStore.mutex.RLock()
	defer tm.tokenStore.mutex.RUnlock()

	tokenID, ok := tm.tokenStore.fingerprintIndex[tokenFingerprint]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}

	storedToken, ok := tm.tokenStore.tokens[tokenID]
	if !ok {
		// Index is out of sync (should not happen); treat as not found.
		return nil, fmt.Errorf("token not found")
	}

	// Constant-time comparison so validation timing does not leak which user a
	// stored token belongs to (L-15).
	if subtle.ConstantTimeCompare([]byte(storedToken.UserID), []byte(userID)) != 1 {
		return nil, fmt.Errorf("token does not belong to requesting user")
	}

	if storedToken.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	// LastUsed is intentionally not updated here: writing through a pointer
	// under RLock races with concurrent ValidateToken callers. LastUsed is not
	// used for any security decision, so it is only updated under write lock
	// paths (StoreToken, performCleanup).
	return storedToken, nil
}

// RevokeToken revokes a token
func (tm *TokenManager) RevokeToken(tokenID string) error {
	tm.tokenStore.mutex.Lock()
	defer tm.tokenStore.mutex.Unlock()

	if storedToken, exists := tm.tokenStore.tokens[tokenID]; exists {
		delete(tm.tokenStore.fingerprintIndex, storedToken.Fingerprint)
		delete(tm.tokenStore.tokens, tokenID)

		log.Debug().
			Str("token_id", tokenID).
			Str("user_id", storedToken.UserID).
			Str("session_id", storedToken.SessionID).
			Msg("Token revoked")

		return nil
	}

	return fmt.Errorf("token not found")
}

// RevokeUserTokens revokes all tokens for a user
func (tm *TokenManager) RevokeUserTokens(userID string) error {
	tm.tokenStore.mutex.Lock()
	defer tm.tokenStore.mutex.Unlock()

	var revokedTokens []string
	for tokenID, storedToken := range tm.tokenStore.tokens {
		if storedToken.UserID == userID {
			delete(tm.tokenStore.fingerprintIndex, storedToken.Fingerprint)
			delete(tm.tokenStore.tokens, tokenID)
			revokedTokens = append(revokedTokens, tokenID)
		}
	}

	log.Debug().
		Str("user_id", userID).
		Int("count", len(revokedTokens)).
		Msg("User tokens revoked")

	return nil
}

// RevokeSessionTokens revokes all tokens for a session
func (tm *TokenManager) RevokeSessionTokens(sessionID string) error {
	tm.tokenStore.mutex.Lock()
	defer tm.tokenStore.mutex.Unlock()

	var revokedTokens []string
	for tokenID, storedToken := range tm.tokenStore.tokens {
		if storedToken.SessionID == sessionID {
			delete(tm.tokenStore.fingerprintIndex, storedToken.Fingerprint)
			delete(tm.tokenStore.tokens, tokenID)
			revokedTokens = append(revokedTokens, tokenID)
		}
	}

	log.Debug().
		Str("session_id", sessionID).
		Int("count", len(revokedTokens)).
		Msg("Session tokens revoked")

	return nil
}

// GetTokenStats returns statistics about stored tokens
func (tm *TokenManager) GetTokenStats() map[string]interface{} {
	tm.tokenStore.mutex.RLock()
	defer tm.tokenStore.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_tokens":   len(tm.tokenStore.tokens),
		"active_tokens":  0,
		"expired_tokens": 0,
		"users":          make(map[string]int),
		"sessions":       make(map[string]int),
	}

	now := time.Now()
	users := make(map[string]int)
	sessions := make(map[string]int)

	for _, token := range tm.tokenStore.tokens {
		if token.ExpiresAt.After(now) {
			stats["active_tokens"] = stats["active_tokens"].(int) + 1
		} else {
			stats["expired_tokens"] = stats["expired_tokens"].(int) + 1
		}

		users[token.UserID]++
		sessions[token.SessionID]++
	}

	stats["users"] = users
	stats["sessions"] = sessions

	return stats
}

// Helper methods

func (tm *TokenManager) generateTokenID() (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}
	return hex.EncodeToString(randomBytes), nil
}

func (tm *TokenManager) removeToken(tokenID string) {
	tm.tokenStore.mutex.Lock()
	defer tm.tokenStore.mutex.Unlock()
	if st, ok := tm.tokenStore.tokens[tokenID]; ok {
		delete(tm.tokenStore.fingerprintIndex, st.Fingerprint)
		delete(tm.tokenStore.tokens, tokenID)
	}
}

func (tm *TokenManager) cleanupExpiredTokens(ctx context.Context) {
	defer tm.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tm.stopChan:
			return
		case <-ticker.C:
			tm.performCleanup()
		}
	}
}

func (tm *TokenManager) performCleanup() {
	tm.tokenStore.mutex.Lock()
	defer tm.tokenStore.mutex.Unlock()

	now := time.Now()
	var expiredTokens []string

	for tokenID, token := range tm.tokenStore.tokens {
		if token.ExpiresAt.Before(now) {
			expiredTokens = append(expiredTokens, tokenID)
		}
	}

	// Remove expired tokens and their index entries
	for _, tokenID := range expiredTokens {
		if st, ok := tm.tokenStore.tokens[tokenID]; ok {
			delete(tm.tokenStore.fingerprintIndex, st.Fingerprint)
		}
		delete(tm.tokenStore.tokens, tokenID)
	}

	if len(expiredTokens) > 0 {
		log.Debug().
			Int("count", len(expiredTokens)).
			Msg("Cleaned up expired tokens")
	}
}
