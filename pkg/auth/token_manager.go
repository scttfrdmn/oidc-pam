package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
)

// TokenManager handles token lifecycle management
type TokenManager struct {
	config      *config.Config
	tokenStore  *TokenStore
	encryption  *security.Encryption
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// TokenStore represents a token storage backend
type TokenStore struct {
	tokens map[string]*StoredToken
	mutex  sync.RWMutex
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

// NewTokenManager creates a new token manager
func NewTokenManager(cfg *config.Config) (*TokenManager, error) {
	// Initialize encryption if enabled
	var encryption *security.Encryption
	if cfg.Security.SecureTokenStorage {
		enc, err := security.NewEncryption(cfg.Security.TokenEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize token encryption: %w", err)
		}
		encryption = enc
	}

	// Initialize token store
	tokenStore := &TokenStore{
		tokens: make(map[string]*StoredToken),
	}

	return &TokenManager{
		config:     cfg,
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

// StoreToken stores a token in the token store
func (tm *TokenManager) StoreToken(token *Token, userID, sessionID string) error {
	// Generate token ID
	tokenID := tm.generateTokenID()

	// Encrypt token if encryption is enabled
	accessToken := token.AccessToken
	refreshToken := token.RefreshToken
	idToken := token.IDToken
	encrypted := false

	if tm.encryption != nil {
		var err error
		accessToken, err = tm.encryption.Encrypt(token.AccessToken)
		if err != nil {
			return fmt.Errorf("failed to encrypt access token: %w", err)
		}

		if token.RefreshToken != "" {
			refreshToken, err = tm.encryption.Encrypt(token.RefreshToken)
			if err != nil {
				return fmt.Errorf("failed to encrypt refresh token: %w", err)
			}
		}

		if token.IDToken != "" {
			idToken, err = tm.encryption.Encrypt(token.IDToken)
			if err != nil {
				return fmt.Errorf("failed to encrypt ID token: %w", err)
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

	// Store in token store
	tm.tokenStore.mutex.Lock()
	tm.tokenStore.tokens[tokenID] = storedToken
	tm.tokenStore.mutex.Unlock()

	log.Debug().
		Str("token_id", tokenID).
		Str("user_id", userID).
		Str("session_id", sessionID).
		Time("expires_at", token.ExpiresAt).
		Bool("encrypted", encrypted).
		Msg("Token stored")

	return nil
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
		accessToken, err = tm.encryption.Decrypt(storedToken.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt access token: %w", err)
		}

		if storedToken.RefreshToken != "" {
			refreshToken, err = tm.encryption.Decrypt(storedToken.RefreshToken)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
			}
		}

		if storedToken.IDToken != "" {
			idToken, err = tm.encryption.Decrypt(storedToken.IDToken)
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

// ValidateToken validates a token
func (tm *TokenManager) ValidateToken(tokenFingerprint string) (*StoredToken, error) {
	tm.tokenStore.mutex.RLock()
	defer tm.tokenStore.mutex.RUnlock()

	// Find token by fingerprint
	for _, storedToken := range tm.tokenStore.tokens {
		if storedToken.Fingerprint == tokenFingerprint {
			// Check if token has expired
			if storedToken.ExpiresAt.Before(time.Now()) {
				return nil, fmt.Errorf("token expired")
			}

			// Update last used time
			storedToken.LastUsed = time.Now()

			return storedToken, nil
		}
	}

	return nil, fmt.Errorf("token not found")
}

// RefreshToken refreshes a token
func (tm *TokenManager) RefreshToken(tokenFingerprint string) (*Token, error) {
	// Find stored token
	storedToken, err := tm.ValidateToken(tokenFingerprint)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Check if token is close to expiry
	if time.Until(storedToken.ExpiresAt) > tm.config.Authentication.RefreshThreshold {
		// Token doesn't need refresh yet
		return tm.GetToken(storedToken.ID)
	}

	// This is a simplified implementation
	// In a real implementation, we would use the refresh token to get a new access token
	log.Debug().
		Str("token_id", storedToken.ID).
		Str("user_id", storedToken.UserID).
		Msg("Token refresh requested")

	return nil, fmt.Errorf("token refresh not implemented")
}

// RevokeToken revokes a token
func (tm *TokenManager) RevokeToken(tokenID string) error {
	tm.tokenStore.mutex.Lock()
	defer tm.tokenStore.mutex.Unlock()

	if storedToken, exists := tm.tokenStore.tokens[tokenID]; exists {
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

func (tm *TokenManager) generateTokenID() string {
	// Generate random bytes
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("token_%d", time.Now().UnixNano())
	}

	// Create hash
	hash := sha256.Sum256(randomBytes)
	return hex.EncodeToString(hash[:])[:16]
}

func (tm *TokenManager) removeToken(tokenID string) {
	tm.tokenStore.mutex.Lock()
	defer tm.tokenStore.mutex.Unlock()
	delete(tm.tokenStore.tokens, tokenID)
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

	// Remove expired tokens
	for _, tokenID := range expiredTokens {
		delete(tm.tokenStore.tokens, tokenID)
	}

	if len(expiredTokens) > 0 {
		log.Debug().
			Int("count", len(expiredTokens)).
			Msg("Cleaned up expired tokens")
	}
}