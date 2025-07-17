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
	
	if km.keySize != 2048 {
		t.Errorf("Expected default keySize 2048, got %d", km.keySize)
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
	defer os.RemoveAll(tempDir)
	
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
	defer os.RemoveAll(tempDir)
	
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
	defer os.RemoveAll(tempDir)
	
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
	defer os.RemoveAll(tempDir)
	
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
		km.GenerateKey(username)
	}
}

func BenchmarkSaveKey(b *testing.B) {
	// Create temporary directory
	tempDir := filepath.Join(os.TempDir(), "bench-keys")
	defer os.RemoveAll(tempDir)
	
	km := NewKeyManager(tempDir)
	username := "benchuser"
	
	key, err := km.GenerateKey(username)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		km.SaveKey(username, key)
	}
}

func BenchmarkLoadKey(b *testing.B) {
	// Create temporary directory
	tempDir := filepath.Join(os.TempDir(), "bench-keys")
	defer os.RemoveAll(tempDir)
	
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
		km.LoadKey(username)
	}
}