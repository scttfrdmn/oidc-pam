package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAddPublicKeyRejectsSymlinkedAuthorizedKeys verifies the C-2 fix: the root
// broker must not follow a symlink planted at authorized_keys to write/append
// into an arbitrary file outside the user's .ssh directory.
func TestAddPublicKeyRejectsSymlinkedAuthorizedKeys(t *testing.T) {
	base := t.TempDir()
	username := "testuser"
	sshDir := filepath.Join(base, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Attacker-controlled target outside .ssh that must NOT be modified.
	target := filepath.Join(base, "victim")
	if err := os.WriteFile(target, []byte("original\n"), 0600); err != nil {
		t.Fatalf("setup target: %v", err)
	}

	// Plant the symlink: ~/.ssh/authorized_keys -> ../../victim
	link := filepath.Join(sshDir, "authorized_keys")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("setup symlink: %v", err)
	}

	akm := NewAuthorizedKeysManager(base)
	err := akm.AddPublicKey(username, []byte("ssh-ed25519 AAAAC3Nz key"))
	if err == nil {
		t.Fatal("expected AddPublicKey to reject symlinked authorized_keys, got nil error")
	}

	// The victim file must be untouched.
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("reading target: %v", readErr)
	}
	if string(data) != "original\n" {
		t.Fatalf("victim file was modified through symlink: %q", string(data))
	}
}

// TestAddPublicKeyRejectsSymlinkedSSHDir verifies a symlinked .ssh directory is
// refused (C-2).
func TestAddPublicKeyRejectsSymlinkedSSHDir(t *testing.T) {
	base := t.TempDir()
	username := "testuser"
	if err := os.MkdirAll(filepath.Join(base, username), 0700); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Point ~/.ssh at an attacker-chosen directory.
	evil := filepath.Join(base, "evil")
	if err := os.MkdirAll(evil, 0700); err != nil {
		t.Fatalf("setup evil dir: %v", err)
	}
	if err := os.Symlink(evil, filepath.Join(base, username, ".ssh")); err != nil {
		t.Fatalf("setup symlink: %v", err)
	}

	akm := NewAuthorizedKeysManager(base)
	if err := akm.AddPublicKey(username, []byte("ssh-ed25519 AAAAC3Nz key")); err == nil {
		t.Fatal("expected AddPublicKey to reject symlinked .ssh dir, got nil error")
	}
}

// TestAddPublicKeyRejectsEmbeddedNewline verifies the M-8 fix: a key value with
// an embedded newline (which would inject a second authorized_keys entry or
// options) is rejected.
func TestAddPublicKeyRejectsEmbeddedNewline(t *testing.T) {
	base := t.TempDir()
	akm := NewAuthorizedKeysManager(base)
	injected := []byte("ssh-ed25519 AAAAreal key\ncommand=\"evil\" ssh-ed25519 AAAAevil key2")
	if err := akm.AddPublicKey("testuser", injected); err == nil {
		t.Fatal("expected AddPublicKey to reject embedded newline, got nil error")
	}
}

func TestValidateUsernameAllowlist(t *testing.T) {
	valid := []string{"alice", "bob_123", "svc-account", "_systemd", "user$"}
	for _, u := range valid {
		if err := validateUsername(u); err != nil {
			t.Errorf("expected %q to be valid, got: %v", u, err)
		}
	}
	invalid := []string{
		"", "..", "../etc", "/etc/passwd", ".", ".ssh",
		"Alice", "user name", "evil;rm", "a\x00b", "1user",
		"toolongusernameusernameusernameusernameusername",
	}
	for _, u := range invalid {
		if err := validateUsername(u); err == nil {
			t.Errorf("expected %q to be rejected", u)
		}
	}
}
