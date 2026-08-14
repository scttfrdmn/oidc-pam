package ssh

import (
	"os"
	"path/filepath"
	"strings"
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

	akm := newTestManager(t, base)
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

	akm := newTestManager(t, base)
	if err := akm.AddPublicKey(username, []byte("ssh-ed25519 AAAAC3Nz key")); err == nil {
		t.Fatal("expected AddPublicKey to reject symlinked .ssh dir, got nil error")
	}
}

// TestAddPublicKeyRejectsEmbeddedNewline verifies the M-8 fix: a key value with
// an embedded newline (which would inject a second authorized_keys entry or
// options) is rejected.
func TestAddPublicKeyRejectsEmbeddedNewline(t *testing.T) {
	base := t.TempDir()
	akm := newTestManager(t, base)
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

// The key store is keyed by an opaque key ID — the broker passes a session ID —
// so validateKeyID has to admit a 64-character hex string while still refusing
// anything that could escape the base directory. Validating that argument as a
// POSIX login name is what broke key provisioning outright (#152).
func TestValidateKeyIDAllowlist(t *testing.T) {
	valid := []string{
		"4de51658fa4527eb9e1894ca69732ec8db2800723c21b516b8434d27b6491b5b", // a real session ID
		"alice", "Session-1", "a", "abc_def-123",
	}
	for _, id := range valid {
		if err := validateKeyID(id); err != nil {
			t.Errorf("expected %q to be a valid key ID, got: %v", id, err)
		}
	}

	invalid := []string{
		"", "..", ".", "../etc", "a/../b", "/etc/passwd", "keys/id_rsa",
		".hidden", "with space", "semi;colon", "nul\x00byte",
		strings.Repeat("a", 129),
	}
	for _, id := range invalid {
		if err := validateKeyID(id); err == nil {
			t.Errorf("expected key ID %q to be rejected", id)
		}
	}
}

// A key ID that a POSIX login name check would refuse must round-trip through the
// store, since that is exactly the shape the broker uses.
func TestSaveAndLoadKeyUnderSessionID(t *testing.T) {
	km := NewKeyManager(t.TempDir())
	km.SetKeySize(2048)

	const sessionID = "4de51658fa4527eb9e1894ca69732ec8db2800723c21b516b8434d27b6491b5b"

	key, err := km.GenerateKey("alice")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := km.SaveKey(sessionID, key); err != nil {
		t.Fatalf("SaveKey under a session ID: %v", err)
	}

	loaded, err := km.LoadKey(sessionID)
	if err != nil {
		t.Fatalf("LoadKey(%q): %v", sessionID, err)
	}
	if string(loaded.PublicKey) != string(key.PublicKey) {
		t.Error("the loaded public key differs from the saved one")
	}

	// The listing has to name both the storage ID and the account the key is for.
	// The store is keyed by session, so the username can only come from the key's
	// own comment — before #152 this column simply showed the session ID.
	infos, unreadable, err := km.ListKeyInfo()
	if err != nil {
		t.Fatalf("ListKeyInfo: %v", err)
	}
	if unreadable != 0 {
		t.Errorf("unreadable = %d, want 0", unreadable)
	}
	if len(infos) != 1 {
		t.Fatalf("ListKeyInfo returned %d keys, want 1", len(infos))
	}
	if infos[0].KeyID != sessionID {
		t.Errorf("KeyID = %q, want %q", infos[0].KeyID, sessionID)
	}
	if infos[0].Username != "alice" {
		t.Errorf("Username = %q, want %q recovered from the key comment", infos[0].Username, "alice")
	}

	if err := km.DeleteKey(sessionID); err != nil {
		t.Fatalf("DeleteKey(%q): %v", sessionID, err)
	}
	if _, err := km.LoadKey(sessionID); err == nil {
		t.Error("LoadKey succeeded after DeleteKey")
	}
}

// usernameFromComment returns "" rather than guessing, so an operator sees an
// empty column instead of a plausible-looking wrong name.
func TestUsernameFromComment(t *testing.T) {
	cases := map[string]string{
		"alice@oidc-pam-1786663703": "alice",
		"svc-account@oidc-pam-0":    "svc-account",
		"alice@oidc-pam-":           "",
		"alice@oidc-pam-notanumber": "",
		"@oidc-pam-1786663703":      "",
		"alice@example.org":         "",
		"":                          "",
	}
	for comment, want := range cases {
		if got := usernameFromComment(comment); got != want {
			t.Errorf("usernameFromComment(%q) = %q, want %q", comment, got, want)
		}
	}
}
