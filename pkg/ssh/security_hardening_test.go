package ssh

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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
	err := akm.AddPublicKey(username, []byte("ssh-ed25519 AAAAC3Nz key"), testExpiry())
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
	if err := akm.AddPublicKey(username, []byte("ssh-ed25519 AAAAC3Nz key"), testExpiry()); err == nil {
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
	if err := akm.AddPublicKey("testuser", injected, testExpiry()); err == nil {
		t.Fatal("expected AddPublicKey to reject embedded newline, got nil error")
	}
}

// validateUsername guards the two places a login name reaches something that can be
// injected into: a path element, and getent(1)'s argv. It is not a statement about
// which accounts exist — NSS answers that.
//
// (#229) The pattern used to be `^[a-z_][a-z0-9_-]{0,31}\$?$`, i.e. lowercase POSIX
// login names only. That is not the population this product deploys into: SSSD
// presents an AD account as `DOMAIN\user` or `user@realm` depending on
// use_fully_qualified_names, and neither form — nor `First.Last`, nor a machine
// account's `$`, nor any capital letter — matched. A site on the modal enterprise
// identity stack had every username refused before authentication was even attempted.
// The cases below that carry a comment are the ones that were rejected before.
func TestValidateUsernameAllowlist(t *testing.T) {
	valid := []string{
		"alice", "bob_123", "svc-account", "_systemd", "user$",
		"Alice",              // a capital letter is legal in a POSIX login name
		"1user",              // so is a leading digit (useradd allows it; NSS certainly does)
		"DOMAIN\\user",       // SSSD, use_fully_qualified_names = false
		"alice@corp.example", // SSSD, use_fully_qualified_names = true
		"First.Last",         // the common AD sAMAccountName shape
		"WORKSTATION$",       // an AD machine account
		"toolongusernameusernameusernameusernameusername",
		strings.Repeat("a", 128), // the bound is a path/argv sanity limit, not 32
	}
	for _, u := range valid {
		if err := validateUsername(u); err != nil {
			t.Errorf("expected %q to be valid, got: %v", u, err)
		}
	}

	// What must stay refused is what is dangerous in a path or an argument list.
	invalid := []string{
		"", "..", "../etc", "/etc/passwd", ".", ".ssh",
		"user name",  // whitespace would also split the broker's key comment
		"user\tname", //
		"alice\n", "evil;rm", "a\x00b",
		"-oProxyCommand",         // getent would read a leading dash as an option
		"a/b",                    // a separator escapes the directory the name is joined into
		strings.Repeat("a", 129), // past the bound
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

// TestNothingInThisPackageChownsByName pins the #203 fix: every handover of a file
// to its account goes through fchown(2) on an open descriptor, never through
// chown(2) on a path.
//
// The distinction is the whole vulnerability. os.Chown resolves the name it is given
// and follows symlinks, and every path this package hands over lives in a directory
// the target account can write — so a chown by name can be redirected at any file on
// the host, and the root broker performs it. That was unreachable while the shipped
// unit withheld CAP_CHOWN (#202); granting the capability is what made it live, which
// is why the two landed together.
//
// This is a source guard rather than a behavioural test, deliberately and with a
// known limit: chownFileToAccount is a no-op for a non-root process, so a test that
// does not run as root cannot observe which file got chowned. What it does catch is
// the reintroduction of os.Chown by someone who does not know the history — which is
// the realistic regression. The behavioural half belongs in the e2e suite, which runs
// as root in a container.
func TestNothingInThisPackageChownsByName(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	// os.Lchown is listed too. It does not follow symlinks, so it is not the
	// escalation — but it still acts on a name, and a name in a user-writable
	// directory can be a different inode by the time the call runs. The descriptor is
	// the only thing this package should be chowning.
	banned := []string{"os.Chown(", "os.Lchown(", "syscall.Chown(", "syscall.Lchown("}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name) // #nosec G304 -- a .go file in this package's own directory
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, call := range banned {
			if strings.Contains(string(source), call) {
				t.Errorf("%s calls %s: hand the file over with chownFileToAccount on an open "+
					"descriptor instead. Chowning a path the account can replace with a symlink "+
					"lets it point the root broker's chown at any file on the host (#203).",
					name, strings.TrimSuffix(call, "("))
			}
		}
	}
}

// everyReadingEntryPoint is every exported operation that reads a user's
// authorized_keys before doing anything else. They are enumerated because the
// hardening below is only worth having if it holds on all of them: a single entry
// point that still follows a symlink, blocks on a FIFO or reads an unbounded file is
// the whole defect, and each of these is reachable from the broker (login, logout,
// session expiry, the periodic sweep) or from oidc-admin.
//
// RestoreAuthorizedKeys is deliberately absent: it reads the *backup*, not the key
// list, so it has its own cases.
func everyReadingEntryPoint(akm *AuthorizedKeysManager, username string) map[string]func() error {
	key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrqnRJYKhFTuTjCGAZ " + username + "@oidc-pam-1")
	return map[string]func() error{
		"AddPublicKey":         func() error { return akm.AddPublicKey(username, key, testExpiry()) },
		"RemovePublicKey":      func() error { _, err := akm.RemovePublicKey(username, key); return err },
		"RemoveOIDCKeys":       func() error { _, err := akm.RemoveOIDCKeys(username); return err },
		"RemoveExpiredKeys":    func() error { return akm.RemoveExpiredKeys(username) },
		"KeyIsAuthorized":      func() error { _, err := akm.KeyIsAuthorized(username, key); return err },
		"ListOIDCKeys":         func() error { _, err := akm.ListOIDCKeys(username); return err },
		"BackupAuthorizedKeys": func() error { return akm.BackupAuthorizedKeys(username) },
	}
}

// (#205) A FIFO where authorized_keys should be must not block the caller.
//
// open(2) on a FIFO for reading blocks until a writer appears, and the open used to
// be plain O_RDONLY|O_NOFOLLOW — which a FIFO passes, since rejectIfSymlink tests
// os.ModeSymlink alone. So `rm ~/.ssh/authorized_keys && mkfifo
// ~/.ssh/authorized_keys` parked the broker in the kernel indefinitely, *inside*
// withFileLock and on the single session-cleanup goroutine: no session would expire
// and no key would be revoked for any account on the host again, and Stop() would
// hang on wg.Wait() until systemd's TimeoutStopSec killed it. One unprivileged user,
// one command, no race to win.
//
// The fix is O_NONBLOCK on the open plus an fstat on the descriptor that came back,
// so what is checked is the object the read would come from rather than what the name
// pointed at earlier.
func TestAFIFOWhereAuthorizedKeysShouldBeCannotWedgeTheBroker(t *testing.T) {
	base := t.TempDir()
	akm := newTestManager(t, base)
	username := "testuser"
	sshDir := filepath.Join(base, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	fifo := filepath.Join(sshDir, "authorized_keys")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	for name, call := range everyReadingEntryPoint(akm, username) {
		t.Run(name, func(t *testing.T) {
			// The deadline is the assertion. Without O_NONBLOCK this call never returns
			// at all, and a test that only checked the error would hang the package until
			// go test's ten-minute timeout with no indication of which call blocked.
			err := runWithin(t, 5*time.Second, name+" with a FIFO where authorized_keys should be (#205)", call)
			if err == nil {
				t.Fatalf("%s accepted a FIFO at %s", name, fifo)
			}
			if !strings.Contains(err.Error(), "not a regular file") {
				t.Errorf("%s refused the FIFO with %v, which does not say the file is not a "+
					"regular one; the refusal has to come from the fstat on the descriptor", name, err)
			}
		})
	}
}

// The same for the backup, which RestoreAuthorizedKeys reads and then installs as an
// account's key list. It lives in the broker's own directory now (#228), so this is
// defence in depth rather than a reachable attack — but it is the one path that writes
// a file's contents into a key list with root's privileges.
func TestAFIFOWhereTheBackupShouldBeCannotWedgeRestore(t *testing.T) {
	base := t.TempDir()
	akm := newTestManager(t, base)
	username := "testuser"
	if err := os.MkdirAll(filepath.Join(base, username, ".ssh"), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	backupPath := akm.BackupPath(username)
	if err := os.MkdirAll(filepath.Dir(backupPath), 0700); err != nil {
		t.Fatalf("MkdirAll backup dir: %v", err)
	}
	if err := syscall.Mkfifo(backupPath, 0600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	err := runWithin(t, 5*time.Second, "RestoreAuthorizedKeys with a FIFO where the backup should be (#205)",
		func() error { return akm.RestoreAuthorizedKeys(username) })
	if err == nil {
		t.Fatalf("RestoreAuthorizedKeys accepted a FIFO at %s", backupPath)
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("the refusal was %v, which does not say the backup is not a regular file", err)
	}
}

// (#206) The whole of authorized_keys is read into memory, so its size has to be
// bounded before the read rather than after. A user can make the file as large as
// their quota allows — and larger than any quota, since a sparse file costs nothing
// to create: `truncate -s 8T ~/.ssh/authorized_keys` is instant and occupies no
// blocks. The broker then tried to allocate it, was killed by the OOM killer or by
// systemd's MemoryMax, and took every other account's session management with it.
//
// The bound is 1 MiB, which is not a guess: the largest entry a real key list can
// hold is under 3 KB (a 16384-bit RSA key is about 2.4 KB of base64, plus options and
// a comment), so 1 MiB is room for roughly 350 of those, 1,300 RSA-4096 entries or
// 10,000 ed25519 ones. No human key list is near it and no generated one should be.
// Reaching the limit is an error rather than a truncation: a key list silently
// missing its tail is one the caller would write straight back out, deleting keys.
func TestAnAbsurdlyLargeAuthorizedKeysIsRefusedRatherThanRead(t *testing.T) {
	base := t.TempDir()
	akm := newTestManager(t, base)
	username := "testuser"
	sshDir := filepath.Join(base, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(sshDir, "authorized_keys")

	// Sparse, so this is instant and costs no disk: exactly how the file would be
	// created in anger.
	const size = 8 << 30 // 8 GiB
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Skipf("this filesystem will not make a sparse %d-byte file: %v", size, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for name, call := range everyReadingEntryPoint(akm, username) {
		t.Run(name, func(t *testing.T) {
			// A deadline as well as an error: reading 8 GiB would not fail, it would
			// take the process out, and a test that waited for that would time out the
			// package rather than report anything.
			err := runWithin(t, 30*time.Second, name+" with an 8 GiB sparse authorized_keys (#206)", call)
			if err == nil {
				t.Fatalf("%s read a %d-byte authorized_keys", name, int64(size))
			}
			if !strings.Contains(err.Error(), "not a key list") {
				t.Errorf("%s failed with %v, which does not say the file was refused for its "+
					"size; the size has to be checked before the read, not after", name, err)
			}
		})
	}
}

// (#225) The temporary file the atomic write goes through used to be named
// .authorized_keys.tmp.<pid>. The broker's pid is public — /proc, ps, systemd's
// MainPID — and the temp file is created in a directory the target account owns, so
// the account could pre-create that exact name and every write through it failed.
// Worse, the name depends on the broker's pid and on nothing else, so the account
// doing the obstructing need not be the account being provisioned: one user could
// stop key provisioning for every account on the host, and two brokers (or a pid
// recycled after a crash) collided on it by accident for the same reason.
//
// os.CreateTemp picks an unpredictable name and creates it O_EXCL, so there is no
// name to squat and nothing to clobber.
func TestAPreCreatedTempNameDoesNotBlockProvisioning(t *testing.T) {
	base := t.TempDir()
	akm := newTestManager(t, base)
	username := "testuser"
	sshDir := filepath.Join(base, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Squat the predictable name with a non-empty directory. That is the version of
	// the defect with no race in it at all: the old code did `os.Remove(tmpPath)`
	// first, which clears a plain file the account planted (and loses a race against
	// an account that recreates it), but rmdir cannot remove a directory with
	// something in it, and the O_CREAT|O_EXCL open that followed then failed with
	// EEXIST on every attempt, for ever.
	squat := filepath.Join(sshDir, ".authorized_keys.tmp."+strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(squat, 0700); err != nil {
		t.Fatalf("Mkdir squat: %v", err)
	}
	if err := os.WriteFile(filepath.Join(squat, "pin"), nil, 0600); err != nil {
		t.Fatalf("WriteFile in squat: %v", err)
	}

	key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrqnRJYKhFTuTjCGAZ testuser@oidc-pam-1")
	if err := akm.AddPublicKey(username, key, testExpiry()); err != nil {
		t.Fatalf("AddPublicKey was blocked by a squatted temp name %s: %v", squat, err)
	}

	content, err := os.ReadFile(filepath.Join(sshDir, "authorized_keys")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(content), "AAAAC3NzaC1lZDI1NTE5AAAAINrqnRJYKhFTuTjCGAZ") {
		t.Errorf("the key was not installed; authorized_keys is %q", content)
	}
}

// (#204) A symlinked .ssh has to be refused by every entry point, not only by the one
// that creates the directory.
//
// Only AddPublicKey went through ensureSecureSSHDir, which lstats .ssh and refuses a
// link. The read-only and removal paths called os.Stat instead — which *follows*
// symlinks, so it reports on the target — and then opened .ssh/authorized_keys, where
// O_NOFOLLOW constrains the final component only and cannot see that a parent
// component was a link. So a user who replaced ~/.ssh with a link to /root/.ssh had
// the broker read root's key list through it and, on the removal paths, rewrite it:
// RemoveOIDCKeys would strip root's broker-issued keys, and RemoveExpiredKeys would
// rewrite the whole file as root's authorized_keys with entries missing. Now every
// entry point goes through checkSSHDir first.
func TestASymlinkedSSHDirIsRefusedByEveryEntryPoint(t *testing.T) {
	base := t.TempDir()
	akm := newTestManager(t, base)
	username := "testuser"

	// Somebody else's key list, reachable only through the link.
	victimDir := filepath.Join(base, "victim-ssh")
	if err := os.MkdirAll(victimDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	const victimContent = "ssh-rsa AAAAB3NzaC1yc2EVICTIM root@oidc-pam-1\n"
	victimKeys := filepath.Join(victimDir, "authorized_keys")
	if err := os.WriteFile(victimKeys, []byte(victimContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(victimDir, filepath.Join(base, username, ".ssh")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	for name, call := range everyReadingEntryPoint(akm, username) {
		t.Run(name, func(t *testing.T) {
			err := call()
			if err == nil {
				t.Fatalf("%s operated on a symlinked .ssh", name)
			}
			if !strings.Contains(err.Error(), "symlink") {
				t.Errorf("%s failed with %v, which does not say the .ssh directory was a "+
					"symlink", name, err)
			}
			data, readErr := os.ReadFile(victimKeys) // #nosec G304 -- test temp dir
			if readErr != nil {
				t.Fatalf("ReadFile: %v", readErr)
			}
			if string(data) != victimContent {
				t.Errorf("%s rewrote another account's key list through the link: %q", name, data)
			}
		})
	}

	// RestoreAuthorizedKeys is the same question from the other side: it must not
	// install a key list through the link either.
	backupPath := akm.BackupPath(username)
	if err := os.MkdirAll(filepath.Dir(backupPath), 0700); err != nil {
		t.Fatalf("MkdirAll backup dir: %v", err)
	}
	if err := os.WriteFile(backupPath, []byte("ssh-ed25519 AAAARESTORED x@oidc-pam-1\n"), 0600); err != nil {
		t.Fatalf("WriteFile backup: %v", err)
	}
	if err := akm.RestoreAuthorizedKeys(username); err == nil {
		t.Error("RestoreAuthorizedKeys wrote a key list through a symlinked .ssh")
	}
	data, err := os.ReadFile(victimKeys) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != victimContent {
		t.Errorf("RestoreAuthorizedKeys overwrote another account's key list: %q", data)
	}
}

// (#225) The durability half of the atomic replace, which cannot be tested from a
// process: proving it needs the power cut, and nothing observable in-process
// distinguishes a write that was fsynced from one that was not.
//
// It still matters. Without the fsync on the file, a host on ext4 with the default
// data=ordered that loses power just after the rename comes back with the directory
// entry durable and the contents not — the documented outcome is a zero-length
// authorized_keys. Every provisioned key for that account is then gone, and nothing
// detects it, because the file exists and parses: the user simply cannot log in by the
// mechanism the broker is responsible for until their next successful login rewrites
// it. Without the fsync on the *directory*, the rename's own durability is unspecified.
//
// So this is a source guard on the order of operations, in the spirit of
// TestNothingInThisPackageChownsByName: it catches the removal of the syncs by someone
// who does not know why they are there, which is the realistic regression, and it
// makes no claim to have observed a crash.
func TestTheAtomicWriteSyncsTheFileBeforeTheRenameAndTheDirectoryAfter(t *testing.T) {
	source, err := os.ReadFile("authorized_keys.go") // #nosec G304 -- this package's own source
	if err != nil {
		t.Fatalf("read authorized_keys.go: %v", err)
	}
	body := functionBody(t, string(source), "func writeAuthorizedKeysAtomic(")

	sync := strings.Index(body, "tmp.Sync()")
	rename := strings.Index(body, "os.Rename(")
	dirSync := strings.Index(body, "syncDir(")

	switch {
	case sync < 0:
		t.Error("writeAuthorizedKeysAtomic does not fsync the temp file. A crash just after " +
			"the rename can then leave a zero-length authorized_keys, silently destroying " +
			"every provisioned key for that account (#225).")
	case rename < 0:
		t.Fatal("writeAuthorizedKeysAtomic no longer renames; this guard needs rewriting")
	case sync > rename:
		t.Errorf("writeAuthorizedKeysAtomic fsyncs the temp file at offset %d, after the "+
			"rename at %d. The point of the fsync is that the contents are durable before "+
			"the name pointing at them is (#225).", sync, rename)
	}
	if dirSync < 0 || dirSync < rename {
		t.Error("writeAuthorizedKeysAtomic does not fsync the .ssh directory after the " +
			"rename, so the rename's durability is unspecified (#225).")
	}
}

// functionBody returns the source text of the function whose declaration starts with
// decl, up to the closing brace in column zero. Crude, and sufficient: it is used to
// ask about the order of statements in one known function.
func functionBody(t *testing.T, source, decl string) string {
	t.Helper()

	start := strings.Index(source, decl)
	if start < 0 {
		t.Fatalf("cannot find %q in the source; this guard needs updating", decl)
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("cannot find the end of %q", decl)
	}
	return source[start : start+end]
}
