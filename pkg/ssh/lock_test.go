package ssh

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// holdLock takes the manager's lock for username the way a competing writer
// would, and holds it until the test ends.
//
// flock ownership belongs to the open file description, not the process, so a
// second os.OpenFile here contends with withFileLock exactly as a separate
// process would — no subprocess needed. Before #161 the equivalent of this in a
// user's shell (`flock ~/.ssh/authorized_keys.lock -c 'sleep infinity'`) was
// enough to stop the broker's cleanup goroutine forever.
func holdLock(t *testing.T, akm *AuthorizedKeysManager, username string) {
	t.Helper()

	if err := ensureLockDir(akm.lockDir); err != nil {
		t.Fatalf("ensureLockDir: %v", err)
	}
	path := akm.LockPath(username)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("open lock file %s: %v", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("flock %s: %v", path, err)
	}
	t.Cleanup(func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	})
}

// seedStaleKey writes a user's authorized_keys with one broker-issued key old
// enough for RemoveExpiredKeys to want to remove it.
func seedStaleKey(t *testing.T, baseDir, username string) string {
	t.Helper()

	sshDir := filepath.Join(baseDir, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(sshDir, "authorized_keys")
	line := "ssh-rsa AAAAB3NzaC1yc2ESTALE " + username + "@oidc-pam-" +
		strconv.FormatInt(time.Now().Add(-48*time.Hour).Unix(), 10)
	if err := os.WriteFile(path, []byte(line+"\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// runWithin runs fn and returns its error, failing the test if fn has not
// returned by limit. Without the guard a regression would hang the whole package
// until `go test` times out ten minutes later with no indication of which call
// blocked.
func runWithin(t *testing.T, limit time.Duration, fn func() error) error {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("call did not return within %s while the lock was held; it is blocking on the lock (#161)", limit)
		return nil
	}
}

// The wedge from #161: the cleanup goroutine's write must give up rather than
// wait forever on a lock someone else holds.
func TestRemoveExpiredKeysGivesUpWhenTheLockIsHeld(t *testing.T) {
	base := t.TempDir()
	akm := newTestManager(t, base, "alice")
	akm.SetLockTimeout(150 * time.Millisecond)

	path := seedStaleKey(t, base, "alice")
	holdLock(t, akm, "alice")

	err := runWithin(t, 5*time.Second, func() error { return akm.RemoveExpiredKeys("alice") })
	if !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("expected ErrLockUnavailable, got %v", err)
	}

	// Failing to take the lock must not mean writing without it: the stale key is
	// still there, to be removed on the next pass.
	data, readErr := os.ReadFile(path) // #nosec G304 -- test temp dir
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if !strings.Contains(string(data), "STALE") {
		t.Error("authorized_keys was rewritten without holding the lock")
	}
}

// The login path has the same property, for a different reason: a hung
// AddPublicKey holds up the authentication it belongs to, and sshd's
// LoginGraceTime would kill the connection with no explanation logged.
func TestAddPublicKeyGivesUpWhenTheLockIsHeld(t *testing.T) {
	base := t.TempDir()
	akm := newTestManager(t, base, "alice")
	akm.SetLockTimeout(150 * time.Millisecond)

	holdLock(t, akm, "alice")

	key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrqnRJYKhFTuTjCGAZ alice@oidc-pam")
	err := runWithin(t, 5*time.Second, func() error { return akm.AddPublicKey("alice", key, testExpiry()) })
	if !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("expected ErrLockUnavailable, got %v", err)
	}
}

// One user's held lock must not affect another user's writes: the locks are
// per-user precisely so that a single uncooperative account cannot stop cleanup
// for the whole host.
func TestOneUsersLockDoesNotBlockAnother(t *testing.T) {
	base := t.TempDir()
	akm := newTestManager(t, base, "alice", "bob")
	akm.SetLockTimeout(150 * time.Millisecond)

	bobPath := seedStaleKey(t, base, "bob")
	seedStaleKey(t, base, "alice")
	holdLock(t, akm, "alice")

	if err := runWithin(t, 5*time.Second, func() error { return akm.RemoveExpiredKeys("bob") }); err != nil {
		t.Fatalf("RemoveExpiredKeys(bob): %v", err)
	}

	data, err := os.ReadFile(bobPath) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "STALE") {
		t.Error("bob's expired key survived because alice was holding her lock")
	}
}

// The other half of the #161 fix: the lock the user could take is gone, because
// the lock is no longer anywhere the user can write.
func TestTheLockIsNotInTheUsersHome(t *testing.T) {
	base := t.TempDir()
	lockDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "alice"), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	akm := NewAuthorizedKeysManager(lockDir)
	akm.SetAccountLookup(HomeRootLookup(base))

	key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrqnRJYKhFTuTjCGAZ alice@oidc-pam")
	if err := akm.AddPublicKey("alice", key, testExpiry()); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	sshDir := filepath.Join(base, "alice", ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".lock") {
			t.Errorf("lock file %s is in the user's own .ssh, where the user can hold it", e.Name())
		}
	}

	if _, err := os.Stat(filepath.Join(lockDir, "alice.lock")); err != nil {
		t.Errorf("expected the lock in the broker's lock directory: %v", err)
	}
}

func TestEnsureLockDirRejectsUnsafeDirectories(t *testing.T) {
	t.Run("group or world writable", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "locks")
		if err := os.Mkdir(dir, 0777); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		// Mkdir applies the umask, so set the mode explicitly.
		if err := os.Chmod(dir, 0777); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		err := ensureLockDir(dir)
		if err == nil || !strings.Contains(err.Error(), "writable by group or other") {
			t.Fatalf("expected a refusal for a world-writable lock dir, got %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		tmp := t.TempDir()
		target := filepath.Join(tmp, "real")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		link := filepath.Join(tmp, "locks")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		err := ensureLockDir(link)
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("expected a refusal for a symlinked lock dir, got %v", err)
		}
	})

	t.Run("not a directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "locks")
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		err := ensureLockDir(path)
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("expected a refusal for a lock dir that is a file, got %v", err)
		}
	})

	t.Run("created when absent", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "nested", "locks")
		if err := ensureLockDir(dir); err != nil {
			t.Fatalf("ensureLockDir: %v", err)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0700 {
			t.Errorf("lock dir created with mode %#o, want 0700", perm)
		}
	})
}
