package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewAuthorizedKeysManager(t *testing.T) {
	baseDir := "/tmp/test-auth-keys"
	akm := NewAuthorizedKeysManager(baseDir)
	
	if akm == nil {
		t.Fatal("Expected non-nil AuthorizedKeysManager")
	}
	if akm.baseDir != baseDir {
		t.Errorf("Expected baseDir %s, got %s", baseDir, akm.baseDir)
	}
}

func TestAddPublicKey(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	publicKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... testuser@example.com")
	
	// Test adding a public key
	err = akm.AddPublicKey(username, publicKey)
	if err != nil {
		t.Errorf("Failed to add public key: %v", err)
	}
	
	// Verify the key was added
	authorizedKeysPath := filepath.Join(tmpDir, username, ".ssh", "authorized_keys")
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Errorf("Failed to read authorized_keys file: %v", err)
	}
	
	content := string(data)
	if !strings.Contains(content, string(publicKey)) {
		t.Error("Public key not found in authorized_keys file")
	}
	if !strings.Contains(content, "# Added by OIDC PAM on") {
		t.Error("Expected timestamp comment not found")
	}
	
	// Test adding the same key again (should not duplicate)
	err = akm.AddPublicKey(username, publicKey)
	if err != nil {
		t.Errorf("Failed to add duplicate public key: %v", err)
	}
	
	// Verify no duplication
	data, err = os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Errorf("Failed to read authorized_keys file: %v", err)
	}
	
	keyCount := strings.Count(string(data), string(publicKey))
	if keyCount != 1 {
		t.Errorf("Expected 1 occurrence of key, found %d", keyCount)
	}
}

func TestAddPublicKeyWithExistingFile(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	sshDir := filepath.Join(tmpDir, username, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	
	// Create .ssh directory and existing authorized_keys file
	err = os.MkdirAll(sshDir, 0700)
	if err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}
	
	existingContent := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... existing@example.com\n"
	err = os.WriteFile(authorizedKeysPath, []byte(existingContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create existing authorized_keys file: %v", err)
	}
	
	// Add a new key
	newKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... newkey@example.com")
	err = akm.AddPublicKey(username, newKey)
	if err != nil {
		t.Errorf("Failed to add public key to existing file: %v", err)
	}
	
	// Verify both keys are present
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Errorf("Failed to read authorized_keys file: %v", err)
	}
	
	content := string(data)
	if !strings.Contains(content, "existing@example.com") {
		t.Error("Existing key not found in authorized_keys file")
	}
	if !strings.Contains(content, string(newKey)) {
		t.Error("New key not found in authorized_keys file")
	}
}

func TestRemovePublicKey(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	publicKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... testuser@example.com")
	
	// Add a public key first
	err = akm.AddPublicKey(username, publicKey)
	if err != nil {
		t.Errorf("Failed to add public key: %v", err)
	}
	
	// Remove the public key
	err = akm.RemovePublicKey(username, publicKey)
	if err != nil {
		t.Errorf("Failed to remove public key: %v", err)
	}
	
	// Verify the key was removed
	authorizedKeysPath := filepath.Join(tmpDir, username, ".ssh", "authorized_keys")
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Errorf("Failed to read authorized_keys file: %v", err)
	}
	
	content := string(data)
	if strings.Contains(content, string(publicKey)) {
		t.Error("Public key still found in authorized_keys file after removal")
	}
}

func TestRemovePublicKeyNonExistentFile(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	publicKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... testuser@example.com")
	
	// Try to remove a key when file doesn't exist
	err = akm.RemovePublicKey(username, publicKey)
	if err != nil {
		t.Errorf("Expected no error when removing key from non-existent file, got: %v", err)
	}
}

func TestRemovePublicKeyNotFound(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	existingKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... existing@example.com")
	nonExistentKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... nonexistent@example.com")
	
	// Add a public key
	err = akm.AddPublicKey(username, existingKey)
	if err != nil {
		t.Errorf("Failed to add public key: %v", err)
	}
	
	// Try to remove a different key
	err = akm.RemovePublicKey(username, nonExistentKey)
	if err != nil {
		t.Errorf("Expected no error when removing non-existent key, got: %v", err)
	}
	
	// Verify the existing key is still there
	authorizedKeysPath := filepath.Join(tmpDir, username, ".ssh", "authorized_keys")
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Errorf("Failed to read authorized_keys file: %v", err)
	}
	
	content := string(data)
	if !strings.Contains(content, string(existingKey)) {
		t.Error("Existing key should still be present")
	}
}

func TestListOIDCKeys(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	sshDir := filepath.Join(tmpDir, username, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	
	// Create .ssh directory and authorized_keys file with mixed keys
	err = os.MkdirAll(sshDir, 0700)
	if err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}
	
	content := `# Regular key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... regular@example.com
# OIDC PAM key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@oidc-pam-123456
# Another regular key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrqnRJYKhFTuTjCGAZ... regular2@example.com
# Another OIDC PAM key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@oidc-pam-789012
`
	err = os.WriteFile(authorizedKeysPath, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create authorized_keys file: %v", err)
	}
	
	// List OIDC keys
	oidcKeys, err := akm.ListOIDCKeys(username)
	if err != nil {
		t.Errorf("Failed to list OIDC keys: %v", err)
	}
	
	if len(oidcKeys) != 2 {
		t.Errorf("Expected 2 OIDC keys, got %d", len(oidcKeys))
	}
	
	// Verify the correct keys are returned
	for _, key := range oidcKeys {
		if !strings.Contains(key, "@oidc-pam-") {
			t.Errorf("Expected OIDC key to contain '@oidc-pam-', got: %s", key)
		}
	}
}

func TestListOIDCKeysNonExistentFile(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	
	// List OIDC keys from non-existent file
	oidcKeys, err := akm.ListOIDCKeys(username)
	if err != nil {
		t.Errorf("Expected no error when listing keys from non-existent file, got: %v", err)
	}
	
	if len(oidcKeys) != 0 {
		t.Errorf("Expected 0 OIDC keys from non-existent file, got %d", len(oidcKeys))
	}
}

func TestBackupAuthorizedKeys(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	sshDir := filepath.Join(tmpDir, username, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	backupPath := filepath.Join(sshDir, "authorized_keys.backup")
	
	// Create .ssh directory and authorized_keys file
	err = os.MkdirAll(sshDir, 0700)
	if err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}
	
	originalContent := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... testuser@example.com\n"
	err = os.WriteFile(authorizedKeysPath, []byte(originalContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create authorized_keys file: %v", err)
	}
	
	// Create backup
	err = akm.BackupAuthorizedKeys(username)
	if err != nil {
		t.Errorf("Failed to create backup: %v", err)
	}
	
	// Verify backup file exists and has correct content
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Errorf("Failed to read backup file: %v", err)
	}
	
	if string(backupData) != originalContent {
		t.Errorf("Backup content doesn't match original. Expected: %s, Got: %s", originalContent, string(backupData))
	}
}

func TestBackupAuthorizedKeysNonExistentFile(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	
	// Try to backup non-existent file
	err = akm.BackupAuthorizedKeys(username)
	if err != nil {
		t.Errorf("Expected no error when backing up non-existent file, got: %v", err)
	}
}

func TestRestoreAuthorizedKeys(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	sshDir := filepath.Join(tmpDir, username, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	backupPath := filepath.Join(sshDir, "authorized_keys.backup")
	
	// Create .ssh directory and backup file
	err = os.MkdirAll(sshDir, 0700)
	if err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}
	
	backupContent := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... backup@example.com\n"
	err = os.WriteFile(backupPath, []byte(backupContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create backup file: %v", err)
	}
	
	// Create different current file
	currentContent := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... current@example.com\n"
	err = os.WriteFile(authorizedKeysPath, []byte(currentContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create current authorized_keys file: %v", err)
	}
	
	// Restore from backup
	err = akm.RestoreAuthorizedKeys(username)
	if err != nil {
		t.Errorf("Failed to restore from backup: %v", err)
	}
	
	// Verify restoration
	restoredData, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Errorf("Failed to read restored file: %v", err)
	}
	
	if string(restoredData) != backupContent {
		t.Errorf("Restored content doesn't match backup. Expected: %s, Got: %s", backupContent, string(restoredData))
	}
}

func TestRestoreAuthorizedKeysNoBackup(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	
	// Try to restore when no backup exists
	err = akm.RestoreAuthorizedKeys(username)
	if err == nil {
		t.Error("Expected error when restoring from non-existent backup")
	}
	if !strings.Contains(err.Error(), "no backup file found") {
		t.Errorf("Expected 'no backup file found' error, got: %v", err)
	}
}

func TestValidateKeyFormat(t *testing.T) {
	akm := NewAuthorizedKeysManager("/tmp")
	
	// Test valid keys
	validKeys := [][]byte{
		[]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@example.com"),
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrqnRJYKhFTuTjCGAZ... user@example.com"),
		[]byte("ssh-dss AAAAB3NzaC1kc3MAAACBAI... user@example.com"),
		[]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG... user@example.com"),
	}
	
	for _, key := range validKeys {
		err := akm.ValidateKeyFormat(key)
		if err != nil {
			t.Errorf("Expected valid key format for %s, got error: %v", string(key), err)
		}
	}
	
	// Test invalid keys
	invalidKeys := [][]byte{
		[]byte(""),                                           // empty key
		[]byte("   "),                                        // whitespace only
		[]byte("invalid-key"),                               // missing key data
		[]byte("ssh-invalid AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@example.com"), // invalid key type
		[]byte("ssh-rsa"),                                   // missing key data
	}
	
	for _, key := range invalidKeys {
		err := akm.ValidateKeyFormat(key)
		if err == nil {
			t.Errorf("Expected error for invalid key format: %s", string(key))
		}
	}
}

func TestRemoveExpiredKeys(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	sshDir := filepath.Join(tmpDir, username, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	
	// Create .ssh directory and authorized_keys file with expired OIDC keys
	err = os.MkdirAll(sshDir, 0700)
	if err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}
	
	// Create timestamps: one expired (25 hours ago), one fresh (1 hour ago)
	expiredTimestamp := time.Now().Add(-25 * time.Hour).Unix()
	freshTimestamp := time.Now().Add(-1 * time.Hour).Unix()
	
	content := fmt.Sprintf(`# Regular key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... regular@example.com
# Expired OIDC key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@oidc-pam-%d
# Fresh OIDC key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@oidc-pam-%d
`, expiredTimestamp, freshTimestamp)
	
	err = os.WriteFile(authorizedKeysPath, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create authorized_keys file: %v", err)
	}
	
	// Remove expired keys
	err = akm.RemoveExpiredKeys(username)
	if err != nil {
		t.Errorf("Failed to remove expired keys: %v", err)
	}
	
	// Verify results
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Errorf("Failed to read authorized_keys file: %v", err)
	}
	
	updatedContent := string(data)
	
	// Regular key should still be there
	if !strings.Contains(updatedContent, "regular@example.com") {
		t.Error("Regular key should still be present")
	}
	
	// Fresh OIDC key should still be there
	if !strings.Contains(updatedContent, fmt.Sprintf("user@oidc-pam-%d", freshTimestamp)) {
		t.Error("Fresh OIDC key should still be present")
	}
	
	// Expired OIDC key should be removed
	if strings.Contains(updatedContent, fmt.Sprintf("user@oidc-pam-%d", expiredTimestamp)) {
		t.Error("Expired OIDC key should have been removed")
	}
}

func TestRemoveExpiredKeysNonExistentFile(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	akm := NewAuthorizedKeysManager(tmpDir)
	username := "testuser"
	
	// Try to remove expired keys from non-existent file
	err = akm.RemoveExpiredKeys(username)
	if err != nil {
		t.Errorf("Expected no error when removing expired keys from non-existent file, got: %v", err)
	}
}