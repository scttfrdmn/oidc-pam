package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestManager builds a manager that resolves homes under baseDir and whose lock
// directory is a fresh temp dir, and creates the home directories of the named
// accounts (defaulting to "testuser").
//
// The homes are created here because the manager refuses to create one itself
// (#171): a missing home means the account is not provisioned on this host, and
// creating it as root locks the user out of it. Tests that are *about* that refusal
// resolve their own paths instead of using this helper.
//
// The lock directory is a separate argument in production too (#161): the locks
// must not be reachable from the homes they protect. A test that pointed lockDir
// at baseDir would still pass while reintroducing exactly the bug, so no test
// shares the two.
func newTestManager(t *testing.T, baseDir string, usernames ...string) *AuthorizedKeysManager {
	t.Helper()
	if len(usernames) == 0 {
		usernames = []string{"testuser"}
	}
	for _, username := range usernames {
		if err := os.MkdirAll(filepath.Join(baseDir, username), 0700); err != nil {
			t.Fatalf("MkdirAll home for %s: %v", username, err)
		}
	}
	akm := NewAuthorizedKeysManager(t.TempDir())
	akm.SetAccountLookup(HomeRootLookup(baseDir))
	return akm
}

// testExpiry is the expiry every test that does not care about expiry passes to
// AddPublicKey. It is far enough out that no sweep in these tests treats it as
// stale, and AddPublicKey refuses a zero or past value outright (#171).
func testExpiry() time.Time { return time.Now().Add(time.Hour) }

func TestNewAuthorizedKeysManager(t *testing.T) {
	lockDir := "/tmp/test-auth-locks"
	akm := NewAuthorizedKeysManager(lockDir)

	if akm == nil {
		t.Fatal("Expected non-nil AuthorizedKeysManager")
	}
	if akm.lockDir != lockDir {
		t.Errorf("Expected lockDir %s, got %s", lockDir, akm.lockDir)
	}
	// Homes come from the account database, never from a base directory the broker
	// guessed (#171).
	if akm.lookupAccount == nil {
		t.Error("a manager built for production has no account lookup, so it cannot resolve a home")
	}
	// The lock must not live under the home directory it protects: a user who can
	// write there can take the lock and wedge the broker (#161).
	if got := akm.LockPath("alice"); !strings.HasPrefix(got, lockDir) {
		t.Errorf("lock path %s is not in the lock directory %s", got, lockDir)
	}
}

// The manager must not invent a home directory. Before #171 it joined "/home" with
// the login name, so on a host whose homes are anywhere else the broker wrote a key
// list sshd never reads — and reported success, letting a login through that could
// not work.
func TestPathsComeFromTheAccountDatabaseNotABaseDirectory(t *testing.T) {
	realHomes := t.TempDir()
	home := filepath.Join(realHomes, "ldap-domain", "alice")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	akm := NewAuthorizedKeysManager(t.TempDir())
	akm.SetAccountLookup(func(username string) (Account, error) {
		if username != "alice" {
			return Account{}, ErrUnknownAccount
		}
		return Account{Username: "alice", Home: home, UID: os.Geteuid(), GID: os.Getegid()}, nil
	})

	key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILDAP alice@oidc-pam-1700000000")
	if err := akm.AddPublicKey("alice", key, testExpiry()); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatalf("the key was not written to the home the account database gave (%s): %v", home, err)
	}
	if !strings.Contains(string(data), "AAAAC3NzaC1lZDI1NTE5AAAAILDAP") {
		t.Errorf("authorized_keys at the real home does not contain the key; content is %q", data)
	}
	// Nothing may have been created at the path the old code would have used.
	if _, err := os.Stat(filepath.Join(realHomes, "alice")); err == nil {
		t.Errorf("a directory was created at %s, which is not this account's home",
			filepath.Join(realHomes, "alice"))
	}
}

// A missing home means the account is not provisioned on this host. The broker must
// say so, not create it: MkdirAll(<home>/.ssh) used to create the home as root with
// mode 0700, locking the user out of their own home directory for a login that
// could not work anyway (#171).
func TestAddPublicKeyRefusesAMissingHomeAndDoesNotCreateIt(t *testing.T) {
	baseDir := t.TempDir()
	akm := NewAuthorizedKeysManager(t.TempDir())
	akm.SetAccountLookup(HomeRootLookup(baseDir))

	key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAANOHOME nohome@oidc-pam-1700000000")
	err := akm.AddPublicKey("nohome", key, testExpiry())
	if err == nil {
		t.Fatal("AddPublicKey reported success for an account with no home directory")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error does not say the home is missing: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(baseDir, "nohome")); statErr == nil {
		t.Errorf("the home directory %s was created; the broker must not create homes",
			filepath.Join(baseDir, "nohome"))
	}
}

// A home, .ssh or authorized_keys owned by some third account is not the target
// user's, and writing a key into it neither authorizes them nor is safe: whoever
// owns it can rewrite it. checkOwner is exercised directly because a test cannot
// create a file owned by another uid without root.
func TestForeignOwnershipIsRefused(t *testing.T) {
	account := Account{Username: "alice", Home: "/home/alice", UID: 1000, GID: 1000}
	dir := t.TempDir()
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}

	if err := checkOwner("home directory", dir, info, Account{Username: "alice", UID: os.Geteuid()}); err != nil {
		t.Errorf("a path owned by the account itself was refused: %v", err)
	}
	// Root-owned is accepted, because sshd's StrictModes accepts it: every component
	// of the path to authorized_keys must belong to the user or to root.
	rootInfo, err := os.Lstat("/")
	if err != nil {
		t.Fatalf(`Lstat("/"): %v`, err)
	}
	if uid, ok := statUID(rootInfo); !ok || uid != 0 {
		t.Skip(`"/" is not owned by uid 0 on this host`)
	}
	if err := checkOwner("home directory", "/", rootInfo, account); err != nil {
		t.Errorf("a root-owned path was refused: %v", err)
	}
	if os.Geteuid() != account.UID && os.Geteuid() != 0 {
		if err := checkOwner("home directory", dir, info, account); err == nil {
			t.Error("a path owned by a third account was accepted")
		}
	}
}

func TestAddPublicKey(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
	username := "testuser"
	publicKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... testuser@example.com")

	// Test adding a public key
	err = akm.AddPublicKey(username, publicKey, testExpiry())
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
	err = akm.AddPublicKey(username, publicKey, testExpiry())
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
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
	err = akm.AddPublicKey(username, newKey, testExpiry())
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
	username := "testuser"
	publicKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... testuser@example.com")

	// Add a public key first
	err = akm.AddPublicKey(username, publicKey, testExpiry())
	if err != nil {
		t.Errorf("Failed to add public key: %v", err)
	}

	// Remove the public key
	removed, err := akm.RemovePublicKey(username, publicKey)
	if err != nil {
		t.Errorf("Failed to remove public key: %v", err)
	}
	if !removed {
		t.Error("RemovePublicKey reported no match for a key it had just added")
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
	username := "testuser"
	publicKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... testuser@example.com")

	// Try to remove a key when file doesn't exist
	removed, err := akm.RemovePublicKey(username, publicKey)
	if err != nil {
		t.Errorf("Expected no error when removing key from non-existent file, got: %v", err)
	}
	if removed {
		t.Error("RemovePublicKey claimed a removal from a file that does not exist")
	}
}

func TestRemovePublicKeyNotFound(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
	username := "testuser"
	existingKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... existing@example.com")
	nonExistentKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... nonexistent@example.com")

	// Add a public key
	err = akm.AddPublicKey(username, existingKey, testExpiry())
	if err != nil {
		t.Errorf("Failed to add public key: %v", err)
	}

	// Try to remove a different key
	removed, err := akm.RemovePublicKey(username, nonExistentKey)
	if err != nil {
		t.Errorf("Expected no error when removing non-existent key, got: %v", err)
	}
	// The caller has to be able to tell this from a real removal, or it audits a
	// revocation that did not happen (#165).
	if removed {
		t.Error("RemovePublicKey reported a removal for a key that was never present")
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
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
	akm := newTestManager(t, t.TempDir())

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
		[]byte(""),            // empty key
		[]byte("   "),         // whitespace only
		[]byte("invalid-key"), // missing key data
		[]byte("ssh-invalid AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@example.com"), // invalid key type
		[]byte("ssh-rsa"), // missing key data
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
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

func TestAddPublicKeyConcurrent(t *testing.T) {
	// Regression test: without file locking, concurrent AddPublicKey calls
	// can produce duplicate keys. Run with -race to verify.
	tmpDir, err := os.MkdirTemp("", "test-auth-keys-concurrent")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
	username := "testuser"

	const goroutines = 20
	key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest concurrent@test")

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if err := akm.AddPublicKey(username, key, testExpiry()); err != nil {
				t.Errorf("AddPublicKey failed: %v", err)
			}
		}()
	}
	wg.Wait()

	// Verify: the key should appear exactly once
	authorizedKeysPath := filepath.Join(tmpDir, username, ".ssh", "authorized_keys")
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		t.Fatalf("Failed to read authorized_keys: %v", err)
	}

	// Counted by entry rather than by exact line: the installed entry carries an
	// expiry-time= option in front of the key (#171).
	target, ok := parseKeyEntry(string(key))
	if !ok {
		t.Fatalf("test key is not a valid entry: %q", key)
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if entry, isEntry := parseKeyEntry(line); isEntry && entry.authorizesSameKeyAs(target) {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Expected key to appear exactly once, found %d occurrences", count)
	}
}

func TestRemoveExpiredKeysNonExistentFile(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test-auth-keys")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	akm := newTestManager(t, tmpDir)
	username := "testuser"

	// Try to remove expired keys from non-existent file
	err = akm.RemoveExpiredKeys(username)
	if err != nil {
		t.Errorf("Expected no error when removing expired keys from non-existent file, got: %v", err)
	}
}
