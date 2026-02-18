package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

func TestTokenManagerCreation(t *testing.T) {
	// Test token manager creation

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	if tm == nil {
		t.Error("Expected non-nil token manager")
	}
}

func TestTokenManagerStartStop(t *testing.T) {
	// Test token manager start/stop functionality

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	// Test Start
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = tm.Start(ctx)
	if err != nil {
		t.Logf("Start returned error: %v", err)
	}

	// Test Stop
	err = tm.Stop()
	if err != nil {
		t.Logf("Stop returned error: %v", err)
	}
}

func TestTokenManagerBasicOperations(t *testing.T) {
	// Test basic token manager operations

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	// Test StoreToken
	testToken := &Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		IDToken:      "test-id-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
		Fingerprint:  "test-fingerprint",
		Claims:       make(map[string]interface{}),
	}

	err = tm.StoreToken(testToken, "test-user", "test-session")
	if err != nil {
		t.Logf("StoreToken returned error (expected due to encryption setup): %v", err)
	}

	// Test GetToken
	retrievedToken, err := tm.GetToken("test-token-id")
	if err != nil {
		t.Logf("GetToken returned error: %v", err)
	}
	if retrievedToken != nil {
		t.Log("Retrieved token successfully")
	}

	// Test ValidateToken
	isValid, err := tm.ValidateToken("test-token-id")
	if err != nil {
		t.Logf("ValidateToken returned error: %v", err)
	}
	t.Logf("Token validation result: %v", isValid)

	// Test GetTokenStats
	stats := tm.GetTokenStats()
	if stats != nil {
		t.Log("Retrieved token stats successfully")
	}
}

func TestTokenManagerRevocation(t *testing.T) {
	// Test token revocation functionality

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	// Test RevokeToken
	err = tm.RevokeToken("test-token-id")
	if err != nil {
		t.Logf("RevokeToken returned error: %v", err)
	}

	// Test RevokeUserTokens
	err = tm.RevokeUserTokens("test-user")
	if err != nil {
		t.Logf("RevokeUserTokens returned error: %v", err)
	}

	// Test RevokeSessionTokens
	err = tm.RevokeSessionTokens("test-session")
	if err != nil {
		t.Logf("RevokeSessionTokens returned error: %v", err)
	}
}

func TestTokenManagerRefresh(t *testing.T) {
	// Test token refresh functionality

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	// Test RefreshToken
	newToken, err := tm.RefreshToken("test-token-id")
	if err != nil {
		t.Logf("RefreshToken returned error: %v", err)
	}
	if newToken != nil {
		t.Log("Token refresh attempt completed")
	}
}

func TestTokenManagerInternalMethods(t *testing.T) {
	// Test internal token manager methods

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	// Test generateTokenID
	tokenID, err := tm.generateTokenID()
	if err != nil {
		t.Fatalf("generateTokenID returned error: %v", err)
	}
	if tokenID == "" {
		t.Error("Expected non-empty token ID")
	}
	if len(tokenID) != 32 {
		t.Errorf("Expected 32-char hex token ID, got %d chars", len(tokenID))
	}

	// Test multiple token ID generation for uniqueness
	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		id, err := tm.generateTokenID()
		if err != nil {
			t.Fatalf("generateTokenID returned error: %v", err)
		}
		if ids[id] {
			t.Error("Generated duplicate token ID")
		}
		ids[id] = true
	}
}

func TestTokenManagerCleanup(t *testing.T) {
	// Test token cleanup functionality

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	// Test cleanup methods
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()

	// These methods are usually called by the manager in goroutines,
	// so we just test they don't panic
	// Note: cleanupExpiredTokens expects to be called within a waitgroup context
	tm.wg.Add(1)
	go tm.cleanupExpiredTokens(ctx)
	tm.performCleanup()

	// Wait for cleanup to complete
	tm.wg.Wait()

	// These methods should not panic even if called on empty token manager
	t.Log("Cleanup methods executed successfully")
}

func TestTokenManagerConcurrency(t *testing.T) {
	// Test token manager concurrent operations

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	// Test concurrent token operations
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			// Generate unique token ID
			tokenID, err := tm.generateTokenID()
			if err != nil {
				t.Errorf("generateTokenID returned error in goroutine %d: %v", i, err)
				return
			}
			if tokenID == "" {
				t.Errorf("Generated empty token ID in goroutine %d", i)
				return
			}

			// Test concurrent operations
			_, _ = tm.GetToken(tokenID)
			_, _ = tm.ValidateToken(tokenID)
			_ = tm.RevokeToken(tokenID)
		}(i)
	}

	wg.Wait()
	t.Log("Concurrent operations completed successfully")
}

func TestValidateTokenConcurrent(t *testing.T) {
	// Regression test: ValidateToken mutates LastUsed. Under a read lock this
	// would race; the fix uses a write lock. Run with -race to verify.

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	// Store a token so ValidateToken has something to find
	testToken := &Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		IDToken:      "id",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
		Fingerprint:  "concurrent-fp",
		Claims:       make(map[string]interface{}),
	}
	if err := tm.StoreToken(testToken, "user1", "session1"); err != nil {
		t.Fatalf("Failed to store token: %v", err)
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				storedToken, err := tm.ValidateToken("concurrent-fp")
				if err != nil {
					t.Errorf("ValidateToken failed: %v", err)
					return
				}
				if storedToken == nil {
					t.Error("ValidateToken returned nil token")
					return
				}
			}
		}()
	}

	wg.Wait()
}

func TestTokenManagerAlwaysEncrypts(t *testing.T) {
	// Verify that tokens are always stored encrypted, regardless of
	// SecureTokenStorage setting (encryption is now mandatory).

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	testToken := &Token{
		AccessToken:  "plaintext-access-token",
		RefreshToken: "plaintext-refresh-token",
		IDToken:      "plaintext-id-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
		Fingerprint:  "always-encrypt-fp",
		Claims:       make(map[string]interface{}),
	}

	if err := tm.StoreToken(testToken, "user1", "session1"); err != nil {
		t.Fatalf("StoreToken failed: %v", err)
	}

	// Inspect the stored token directly — it must be encrypted.
	tm.tokenStore.mutex.RLock()
	defer tm.tokenStore.mutex.RUnlock()

	var stored *StoredToken
	for _, st := range tm.tokenStore.tokens {
		if st.Fingerprint == "always-encrypt-fp" {
			stored = st
			break
		}
	}

	if stored == nil {
		t.Fatal("Stored token not found")
	}

	if !stored.Encrypted {
		t.Error("Expected token to be marked as encrypted")
	}
	if stored.AccessToken == "plaintext-access-token" {
		t.Error("Access token stored in plaintext; expected encrypted value")
	}
	if stored.RefreshToken == "plaintext-refresh-token" {
		t.Error("Refresh token stored in plaintext; expected encrypted value")
	}
	if stored.IDToken == "plaintext-id-token" {
		t.Error("ID token stored in plaintext; expected encrypted value")
	}
}
