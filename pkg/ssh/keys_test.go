package ssh

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewKeyManager(t *testing.T) {
	baseDir := "/tmp/test-keys"
	km := NewKeyManager(baseDir)

	if km.baseDir != baseDir {
		t.Errorf("Expected baseDir %s, got %s", baseDir, km.baseDir)
	}

	if km.keySize != 4096 {
		t.Errorf("Expected default keySize 4096, got %d", km.keySize)
	}

	if km.keyType != "rsa" {
		t.Errorf("Expected default keyType 'rsa', got %s", km.keyType)
	}

	if km.expiration != 24*time.Hour {
		t.Errorf("Expected default expiration 24h, got %v", km.expiration)
	}
}

func TestSetters(t *testing.T) {
	km := NewKeyManager("/tmp/test")

	km.SetKeySize(4096)
	if km.keySize != 4096 {
		t.Errorf("Expected keySize 4096, got %d", km.keySize)
	}

	km.SetKeyType("ed25519")
	if km.keyType != "ed25519" {
		t.Errorf("Expected keyType 'ed25519', got %s", km.keyType)
	}

	expiration := 12 * time.Hour
	km.SetExpiration(expiration)
	if km.expiration != expiration {
		t.Errorf("Expected expiration %v, got %v", expiration, km.expiration)
	}
}

func TestGenerateKey(t *testing.T) {
	km := NewKeyManager("/tmp/test-keys")
	username := "testuser"

	key, err := km.GenerateKey(username)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if key == nil {
		t.Fatal("Generated key is nil")
	}

	if len(key.PrivateKey) == 0 {
		t.Error("Private key is empty")
	}

	if len(key.PublicKey) == 0 {
		t.Error("Public key is empty")
	}

	if key.Comment == "" {
		t.Error("Comment is empty")
	}

	if key.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}

	if key.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}

	if key.ExpiresAt.Before(key.CreatedAt) {
		t.Error("ExpiresAt is before CreatedAt")
	}

	// Check that comment contains expected format
	expectedPrefix := username + "@oidc-pam-"
	if len(key.Comment) < len(expectedPrefix) || key.Comment[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("Expected comment to start with %s, got %s", expectedPrefix, key.Comment)
	}
}

func TestSaveAndLoadKey(t *testing.T) {
	// Create temporary directory
	tempDir := filepath.Join(os.TempDir(), "test-keys")
	defer func() { _ = os.RemoveAll(tempDir) }()

	km := NewKeyManager(tempDir)
	username := "testuser"

	// Generate key
	key, err := km.GenerateKey(username)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Save key
	if err := km.SaveKey(username, key); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}

	// Load key
	loadedKey, err := km.LoadKey(username)
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}

	// Compare keys
	if string(loadedKey.PrivateKey) != string(key.PrivateKey) {
		t.Error("Private key mismatch")
	}

	if string(loadedKey.PublicKey) != string(key.PublicKey) {
		t.Error("Public key mismatch")
	}

	if loadedKey.Comment != key.Comment {
		t.Error("Comment mismatch")
	}

	// Allow for 1 second difference due to Unix timestamp precision
	if loadedKey.CreatedAt.Unix() != key.CreatedAt.Unix() {
		t.Error("CreatedAt mismatch")
	}

	if loadedKey.ExpiresAt.Unix() != key.ExpiresAt.Unix() {
		t.Error("ExpiresAt mismatch")
	}
}

func TestDeleteKey(t *testing.T) {
	// Create temporary directory
	tempDir := filepath.Join(os.TempDir(), "test-keys")
	defer func() { _ = os.RemoveAll(tempDir) }()

	km := NewKeyManager(tempDir)
	username := "testuser"

	// Generate and save key
	key, err := km.GenerateKey(username)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if err := km.SaveKey(username, key); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}

	// Verify key exists
	if _, err := km.LoadKey(username); err != nil {
		t.Fatalf("Failed to load key before deletion: %v", err)
	}

	// Delete key
	if err := km.DeleteKey(username); err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify key is deleted
	if _, err := km.LoadKey(username); err == nil {
		t.Error("Expected error when loading deleted key")
	}
}

func TestIsKeyExpired(t *testing.T) {
	km := NewKeyManager("/tmp/test")

	// Test non-expired key
	key := &SSHKey{
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	if km.IsKeyExpired(key) {
		t.Error("Expected key to not be expired")
	}

	// Test expired key
	key.ExpiresAt = time.Now().Add(-1 * time.Hour)

	if !km.IsKeyExpired(key) {
		t.Error("Expected key to be expired")
	}
}

func TestGetKeyPaths(t *testing.T) {
	baseDir := "/tmp/test-keys"
	km := NewKeyManager(baseDir)
	username := "testuser"

	expectedPrivatePath := filepath.Join(baseDir, username, "id_rsa")
	expectedPublicPath := filepath.Join(baseDir, username, "id_rsa.pub")

	if km.GetKeyPath(username) != expectedPrivatePath {
		t.Errorf("Expected private key path %s, got %s", expectedPrivatePath, km.GetKeyPath(username))
	}

	if km.GetPublicKeyPath(username) != expectedPublicPath {
		t.Errorf("Expected public key path %s, got %s", expectedPublicPath, km.GetPublicKeyPath(username))
	}
}

func TestListKeys(t *testing.T) {
	// Create temporary directory
	tempDir := filepath.Join(os.TempDir(), "test-keys")
	defer func() { _ = os.RemoveAll(tempDir) }()

	km := NewKeyManager(tempDir)

	// Initially should be empty
	users, err := km.ListKeys()
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}

	if len(users) != 0 {
		t.Errorf("Expected 0 users, got %d", len(users))
	}

	// Add some keys
	usernames := []string{"user1", "user2", "user3"}
	for _, username := range usernames {
		key, err := km.GenerateKey(username)
		if err != nil {
			t.Fatalf("Failed to generate key for %s: %v", username, err)
		}

		if err := km.SaveKey(username, key); err != nil {
			t.Fatalf("Failed to save key for %s: %v", username, err)
		}
	}

	// List keys again
	users, err = km.ListKeys()
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}

	if len(users) != len(usernames) {
		t.Errorf("Expected %d users, got %d", len(usernames), len(users))
	}

	// Check that all users are present
	for _, username := range usernames {
		found := false
		for _, user := range users {
			if user == username {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find user %s in list", username)
		}
	}
}

func TestCleanupExpiredKeys(t *testing.T) {
	// Create temporary directory
	tempDir := filepath.Join(os.TempDir(), "test-keys")
	defer func() { _ = os.RemoveAll(tempDir) }()

	km := NewKeyManager(tempDir)
	km.SetExpiration(1 * time.Millisecond) // Very short expiration for testing

	// Create expired key
	key, err := km.GenerateKey("expired_user")
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if err := km.SaveKey("expired_user", key); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}

	// Wait for expiration
	time.Sleep(2 * time.Millisecond)

	// Create non-expired key
	km.SetExpiration(1 * time.Hour)
	key2, err := km.GenerateKey("active_user")
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if err := km.SaveKey("active_user", key2); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}

	// Cleanup expired keys
	if err := km.CleanupExpiredKeys(); err != nil {
		t.Fatalf("Failed to cleanup expired keys: %v", err)
	}

	// Check that expired key is removed
	if _, err := km.LoadKey("expired_user"); err == nil {
		t.Error("Expected expired key to be removed")
	}

	// Check that active key is still there
	if _, err := km.LoadKey("active_user"); err != nil {
		t.Errorf("Expected active key to still exist: %v", err)
	}
}

func TestParseMetadata(t *testing.T) {
	data := "created_at=1609459200\nexpires_at=1609545600\ncomment=test@oidc-pam-123\n"

	metadata := parseMetadata(data)

	if metadata["created_at"] != "1609459200" {
		t.Errorf("Expected created_at '1609459200', got %s", metadata["created_at"])
	}

	if metadata["expires_at"] != "1609545600" {
		t.Errorf("Expected expires_at '1609545600', got %s", metadata["expires_at"])
	}

	if metadata["comment"] != "test@oidc-pam-123" {
		t.Errorf("Expected comment 'test@oidc-pam-123', got %s", metadata["comment"])
	}
}

func TestParseTimestamp(t *testing.T) {
	// Test valid timestamp
	ts, err := parseTimestamp("1609459200")
	if err != nil {
		t.Fatalf("Failed to parse valid timestamp: %v", err)
	}

	expected := time.Unix(1609459200, 0)
	if !ts.Equal(expected) {
		t.Errorf("Expected timestamp %v, got %v", expected, ts)
	}

	// Test invalid timestamp
	_, err = parseTimestamp("invalid")
	if err == nil {
		t.Error("Expected error for invalid timestamp")
	}

	// Test empty timestamp
	_, err = parseTimestamp("")
	if err == nil {
		t.Error("Expected error for empty timestamp")
	}
}

// Benchmark tests
func BenchmarkGenerateKey(b *testing.B) {
	km := NewKeyManager("/tmp/bench-keys")
	username := "benchuser"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = km.GenerateKey(username)
	}
}

func BenchmarkSaveKey(b *testing.B) {
	// Create temporary directory
	tempDir := filepath.Join(os.TempDir(), "bench-keys")
	defer func() { _ = os.RemoveAll(tempDir) }()

	km := NewKeyManager(tempDir)
	username := "benchuser"

	key, err := km.GenerateKey(username)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = km.SaveKey(username, key)
	}
}

func BenchmarkLoadKey(b *testing.B) {
	// Create temporary directory
	tempDir := filepath.Join(os.TempDir(), "bench-keys")
	defer func() { _ = os.RemoveAll(tempDir) }()

	km := NewKeyManager(tempDir)
	username := "benchuser"

	key, err := km.GenerateKey(username)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	if err := km.SaveKey(username, key); err != nil {
		b.Fatalf("Failed to save key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = km.LoadKey(username)
	}
}

func TestListKeyInfoReportsAlgorithmSizeAndExpiry(t *testing.T) {
	tempDir := t.TempDir()

	km := NewKeyManager(tempDir)
	// 2048 bits rather than the 4096-bit default: this test is about reading the
	// size back off the public key, and RSA generation dominates its runtime.
	km.SetKeySize(2048)

	km.SetExpiration(-time.Hour) // already expired
	expired, err := km.GenerateKey("expired_user")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := km.SaveKey("expired_user", expired); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}

	km.SetExpiration(time.Hour)
	active, err := km.GenerateKey("active_user")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := km.SaveKey("active_user", active); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}

	infos, unreadable, err := km.ListKeyInfo()
	if err != nil {
		t.Fatalf("ListKeyInfo: %v", err)
	}
	if unreadable != 0 {
		t.Errorf("unreadable = %d, want 0", unreadable)
	}
	if len(infos) != 2 {
		t.Fatalf("got %d keys, want 2", len(infos))
	}

	byUser := make(map[string]KeyInfo, len(infos))
	for _, info := range infos {
		byUser[info.Username] = info
	}

	for username, wantExpired := range map[string]bool{"expired_user": true, "active_user": false} {
		info, ok := byUser[username]
		if !ok {
			t.Fatalf("%s missing from listing", username)
		}
		if info.KeyType != "ssh-rsa" {
			t.Errorf("%s key type = %q, want ssh-rsa", username, info.KeyType)
		}
		if info.KeySize != 2048 {
			t.Errorf("%s key size = %d, want 2048", username, info.KeySize)
		}
		if info.Expired != wantExpired {
			t.Errorf("%s expired = %v, want %v", username, info.Expired, wantExpired)
		}
		if info.CreatedAt.IsZero() || info.ExpiresAt.IsZero() {
			t.Errorf("%s has zero timestamps: created=%v expires=%v", username, info.CreatedAt, info.ExpiresAt)
		}
	}
}

// A key directory that cannot be read must not take the whole listing down with
// it, but it must be counted: a silently short list reads as "these are all the
// keys".
func TestListKeyInfoSkipsAndCountsUnreadableKeys(t *testing.T) {
	tempDir := t.TempDir()

	km := NewKeyManager(tempDir)
	km.SetKeySize(2048)

	key, err := km.GenerateKey("good_user")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := km.SaveKey("good_user", key); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}

	// A directory with a private key but no metadata: what a half-finished
	// SaveKey leaves behind. ListKeys finds it, LoadKey cannot read it.
	brokenDir := filepath.Join(tempDir, "broken_user")
	if err := os.MkdirAll(brokenDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(brokenDir, "id_rsa"), []byte("not a key"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	infos, unreadable, err := km.ListKeyInfo()
	if err != nil {
		t.Fatalf("ListKeyInfo: %v", err)
	}
	if unreadable != 1 {
		t.Errorf("unreadable = %d, want 1", unreadable)
	}
	if len(infos) != 1 || infos[0].Username != "good_user" {
		t.Fatalf("got %+v, want just good_user", infos)
	}
}

func TestListKeyInfoOnMissingBaseDir(t *testing.T) {
	km := NewKeyManager(filepath.Join(t.TempDir(), "does-not-exist"))

	infos, unreadable, err := km.ListKeyInfo()
	if err != nil {
		t.Fatalf("ListKeyInfo on a missing base dir should not error: %v", err)
	}
	if len(infos) != 0 || unreadable != 0 {
		t.Errorf("got %d keys / %d unreadable, want 0/0", len(infos), unreadable)
	}
}

func TestPublicKeyStrengthOnUnparseableKey(t *testing.T) {
	keyType, keySize := publicKeyStrength([]byte("this is not an authorized_keys line"))
	if keyType != "unknown" || keySize != 0 {
		t.Errorf("got (%q, %d), want (\"unknown\", 0)", keyType, keySize)
	}
}
