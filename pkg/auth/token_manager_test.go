package auth

import (
	"context"
	"fmt"
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
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
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
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
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
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
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

	tokenID, err := tm.StoreToken(testToken, "test-user", "test-session")
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}
	if tokenID == "" {
		t.Fatal("StoreToken returned an empty token ID")
	}

	// A round trip returns the original plaintext, so the ID is all a caller
	// needs to keep.
	retrievedToken, err := tm.GetToken(tokenID)
	if err != nil {
		t.Fatalf("GetToken(%q): %v", tokenID, err)
	}
	if retrievedToken.AccessToken != testToken.AccessToken {
		t.Errorf("access token = %q, want %q", retrievedToken.AccessToken, testToken.AccessToken)
	}
	if retrievedToken.RefreshToken != testToken.RefreshToken {
		t.Errorf("refresh token = %q, want %q", retrievedToken.RefreshToken, testToken.RefreshToken)
	}

	// Test ValidateToken
	stored, err := tm.ValidateToken("test-fingerprint", "test-user")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if stored.ID != tokenID {
		t.Errorf("ValidateToken returned token %q, want %q", stored.ID, tokenID)
	}

	// Test GetTokenStats
	stats := tm.GetTokenStats()
	if stats == nil {
		t.Error("expected non-nil token stats")
	}
}

// TestStoredCiphertextDoesNotOpenInAnotherRecord covers #232: an encrypted token
// is bound to the account, session and field it was stored for, so a ciphertext
// moved into another record no longer decrypts.
//
// The scenario is an attacker with write access to the store but not the key. It
// used to succeed in silence: GCM validated the tag, GetToken returned the
// plaintext, and the broker refreshed one user's credentials while attributing
// everything it then did — policy, audit, key provisioning — to the other. A
// failure to decrypt is the outcome that leaves a trace.
func TestStoredCiphertextDoesNotOpenInAnotherRecord(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		},
	}
	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	const aliceRefresh = "alices-refresh-token"
	aliceID, err := tm.StoreToken(&Token{
		AccessToken:  "alices-access-token",
		RefreshToken: aliceRefresh,
		ExpiresAt:    time.Now().Add(time.Hour),
		Fingerprint:  "alice-fp",
	}, "alice", "session-alice")
	if err != nil {
		t.Fatalf("StoreToken(alice): %v", err)
	}

	bobID, err := tm.StoreToken(&Token{
		AccessToken:  "bobs-access-token",
		RefreshToken: "bobs-refresh-token",
		ExpiresAt:    time.Now().Add(time.Hour),
		Fingerprint:  "bob-fp",
	}, "bob", "session-bob")
	if err != nil {
		t.Fatalf("StoreToken(bob): %v", err)
	}

	tm.tokenStore.mutex.Lock()
	alicesCiphertext := tm.tokenStore.tokens[aliceID].RefreshToken
	alicesAccessCiphertext := tm.tokenStore.tokens[aliceID].AccessToken
	// The attack: alice's refresh token, verbatim, in bob's record.
	tm.tokenStore.tokens[bobID].RefreshToken = alicesCiphertext
	tm.tokenStore.mutex.Unlock()

	if alicesCiphertext == aliceRefresh {
		t.Fatal("the refresh token was stored in plaintext; this test would prove nothing")
	}

	token, err := tm.GetToken(bobID)
	if err == nil {
		t.Errorf("bob's record opened alice's refresh token: got %q", token.RefreshToken)
	}

	// Alice's own record is untouched and must still work: the binding may not
	// cost the legitimate read.
	if token, err := tm.GetToken(aliceID); err != nil {
		t.Errorf("GetToken(alice): %v", err)
	} else if token.RefreshToken != aliceRefresh {
		t.Errorf("alice's refresh token = %q, want %q", token.RefreshToken, aliceRefresh)
	}

	// A ciphertext is also bound to the field it was written to, so an access
	// token cannot be promoted into the refresh_token slot of its own record and
	// then presented to the provider as one.
	tm.tokenStore.mutex.Lock()
	tm.tokenStore.tokens[aliceID].RefreshToken = alicesAccessCiphertext
	tm.tokenStore.mutex.Unlock()

	if token, err := tm.GetToken(aliceID); err == nil {
		t.Errorf("an access token opened in the refresh_token field: got %q", token.RefreshToken)
	}
}

func TestTokenManagerRevocation(t *testing.T) {
	// Test token revocation functionality

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
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

func TestTokenManagerInternalMethods(t *testing.T) {
	// Test internal token manager methods

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
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
	if len(tokenID) != 64 {
		t.Errorf("Expected 64-char hex token ID, got %d chars", len(tokenID))
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
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
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
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
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
			_, _ = tm.ValidateToken(tokenID, fmt.Sprintf("user-%d", i))
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
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
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
	if _, err := tm.StoreToken(testToken, "user1", "session1"); err != nil {
		t.Fatalf("Failed to store token: %v", err)
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				storedToken, err := tm.ValidateToken("concurrent-fp", "user1")
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

// newTMForTest returns a ready-to-use TokenManager with encryption configured.
func newTMForTest(t *testing.T) *TokenManager {
	t.Helper()
	tm, err := NewTokenManager(&config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		},
	})
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return tm
}

// storeTestToken stores a token with the given fingerprint and returns it.
func storeTestToken(t *testing.T, tm *TokenManager, fp string) *Token {
	t.Helper()
	tok := &Token{
		AccessToken: "access-" + fp,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
		Fingerprint: fp,
		Claims:      make(map[string]interface{}),
	}
	if _, err := tm.StoreToken(tok, "user1", "sess1"); err != nil {
		t.Fatalf("StoreToken(%q): %v", fp, err)
	}
	return tok
}

// TestFingerprintIndexPopulatedOnStore verifies that StoreToken adds an entry
// to the fingerprint index.
func TestFingerprintIndexPopulatedOnStore(t *testing.T) {
	tm := newTMForTest(t)
	storeTestToken(t, tm, "fp-store-test")

	tm.tokenStore.mutex.RLock()
	_, ok := tm.tokenStore.fingerprintIndex["fp-store-test"]
	tm.tokenStore.mutex.RUnlock()

	if !ok {
		t.Error("Expected fingerprint index to contain the stored fingerprint")
	}
}

// TestFingerprintIndexRemovedOnRevoke verifies that RevokeToken removes the
// fingerprint index entry.
func TestFingerprintIndexRemovedOnRevoke(t *testing.T) {
	tm := newTMForTest(t)
	storeTestToken(t, tm, "fp-revoke-test")

	// Find the tokenID from the index, then revoke it.
	tm.tokenStore.mutex.RLock()
	tokenID := tm.tokenStore.fingerprintIndex["fp-revoke-test"]
	tm.tokenStore.mutex.RUnlock()

	if err := tm.RevokeToken(tokenID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	tm.tokenStore.mutex.RLock()
	_, ok := tm.tokenStore.fingerprintIndex["fp-revoke-test"]
	tm.tokenStore.mutex.RUnlock()

	if ok {
		t.Error("Expected fingerprint index entry to be removed after revoke")
	}
}

// TestFingerprintIndexRemovedOnCleanup verifies that performCleanup removes
// expired tokens' fingerprint index entries.
func TestFingerprintIndexRemovedOnCleanup(t *testing.T) {
	tm := newTMForTest(t)

	// Store a token that is already expired.
	tok := &Token{
		AccessToken: "expired-access",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(-time.Minute), // already expired
		Fingerprint: "fp-cleanup-test",
		Claims:      make(map[string]interface{}),
	}
	if _, err := tm.StoreToken(tok, "user1", "sess1"); err != nil {
		t.Fatalf("StoreToken: %v", err)
	}

	tm.performCleanup()

	tm.tokenStore.mutex.RLock()
	_, inTokens := tm.tokenStore.tokens[tm.tokenStore.fingerprintIndex["fp-cleanup-test"]]
	_, inIndex := tm.tokenStore.fingerprintIndex["fp-cleanup-test"]
	tm.tokenStore.mutex.RUnlock()

	if inTokens || inIndex {
		t.Error("Expected expired token and its index entry to be removed after cleanup")
	}
}

// TestFingerprintIndexRemovedByUserRevoke verifies RevokeUserTokens cleans the index.
func TestFingerprintIndexRemovedByUserRevoke(t *testing.T) {
	tm := newTMForTest(t)
	storeTestToken(t, tm, "fp-user-revoke")

	if err := tm.RevokeUserTokens("user1"); err != nil {
		t.Fatalf("RevokeUserTokens: %v", err)
	}

	tm.tokenStore.mutex.RLock()
	_, ok := tm.tokenStore.fingerprintIndex["fp-user-revoke"]
	tm.tokenStore.mutex.RUnlock()

	if ok {
		t.Error("Expected index entry removed after RevokeUserTokens")
	}
}

// TestFingerprintIndexRemovedBySessionRevoke verifies RevokeSessionTokens
// cleans the index.
func TestFingerprintIndexRemovedBySessionRevoke(t *testing.T) {
	tm := newTMForTest(t)
	storeTestToken(t, tm, "fp-session-revoke")

	if err := tm.RevokeSessionTokens("sess1"); err != nil {
		t.Fatalf("RevokeSessionTokens: %v", err)
	}

	tm.tokenStore.mutex.RLock()
	_, ok := tm.tokenStore.fingerprintIndex["fp-session-revoke"]
	tm.tokenStore.mutex.RUnlock()

	if ok {
		t.Error("Expected index entry removed after RevokeSessionTokens")
	}
}

// TestValidateTokenO1 stores a large number of tokens and validates one that
// sits in the middle, confirming the O(1) path works correctly regardless of
// store size.
func TestValidateTokenO1(t *testing.T) {
	tm := newTMForTest(t)

	const n = 200
	var targetFP string
	for i := 0; i < n; i++ {
		fp := fmt.Sprintf("fp-%04d", i)
		storeTestToken(t, tm, fp)
		if i == n/2 {
			targetFP = fp
		}
	}

	st, err := tm.ValidateToken(targetFP, "user1")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if st.Fingerprint != targetFP {
		t.Errorf("Expected fingerprint %q, got %q", targetFP, st.Fingerprint)
	}
}

// TestValidateTokenIndexConsistency verifies that the fingerprint index and
// the token map stay in sync across a sequence of stores and revocations.
func TestValidateTokenIndexConsistency(t *testing.T) {
	tm := newTMForTest(t)

	for i := 0; i < 10; i++ {
		storeTestToken(t, tm, fmt.Sprintf("fp-consistency-%d", i))
	}

	// Revoke half of them via RevokeUserTokens.
	if err := tm.RevokeUserTokens("user1"); err != nil {
		t.Fatalf("RevokeUserTokens: %v", err)
	}

	tm.tokenStore.mutex.RLock()
	tokenCount := len(tm.tokenStore.tokens)
	indexCount := len(tm.tokenStore.fingerprintIndex)
	tm.tokenStore.mutex.RUnlock()

	if tokenCount != indexCount {
		t.Errorf("Token map (%d) and fingerprint index (%d) are out of sync", tokenCount, indexCount)
	}
}

// BenchmarkValidateToken measures ValidateToken throughput with a populated
// store.  Run with: go test -bench=BenchmarkValidateToken -benchmem ./pkg/auth/
func BenchmarkValidateToken(b *testing.B) {
	tm, err := NewTokenManager(&config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "benchmark-key-that-is-long-enough-for-security",
		},
	})
	if err != nil {
		b.Fatalf("NewTokenManager: %v", err)
	}

	// Pre-populate the store with 1000 tokens.
	const storeSize = 1000
	fps := make([]string, storeSize)
	for i := 0; i < storeSize; i++ {
		fp := fmt.Sprintf("bench-fp-%04d", i)
		fps[i] = fp
		tok := &Token{
			AccessToken: "access-" + fp,
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
			Fingerprint: fp,
			Claims:      make(map[string]interface{}),
		}
		if _, err := tm.StoreToken(tok, "user", "sess"); err != nil {
			b.Fatalf("StoreToken: %v", err)
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			fp := fps[i%storeSize]
			if _, err := tm.ValidateToken(fp, "user"); err != nil {
				b.Errorf("ValidateToken(%q): %v", fp, err)
			}
			i++
		}
	})
}

// BenchmarkValidateTokenSerial is a serial variant of BenchmarkValidateToken
// that shows single-goroutine latency.
func BenchmarkValidateTokenSerial(b *testing.B) {
	tm, err := NewTokenManager(&config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "benchmark-key-that-is-long-enough-for-security",
		},
	})
	if err != nil {
		b.Fatalf("NewTokenManager: %v", err)
	}

	const storeSize = 1000
	fps := make([]string, storeSize)
	for i := 0; i < storeSize; i++ {
		fp := fmt.Sprintf("bench-serial-fp-%04d", i)
		fps[i] = fp
		tok := &Token{
			AccessToken: "access-" + fp,
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
			Fingerprint: fp,
			Claims:      make(map[string]interface{}),
		}
		if _, err := tm.StoreToken(tok, "user", "sess"); err != nil {
			b.Fatalf("StoreToken: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp := fps[i%storeSize]
		if _, err := tm.ValidateToken(fp, "user"); err != nil {
			b.Errorf("ValidateToken(%q): %v", fp, err)
		}
	}
}

func TestTokenManagerAlwaysEncrypts(t *testing.T) {
	// Verify that tokens are always stored encrypted, regardless of
	// SecureTokenStorage setting (encryption is now mandatory).

	cfg := &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
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

	if _, err := tm.StoreToken(testToken, "user1", "session1"); err != nil {
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
