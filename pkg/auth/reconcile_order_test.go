package auth

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// reconcileIssuedKeys has two things to do per orphaned key: remove the entry from
// the account's authorized_keys, and delete the record of it from the broker's own
// key store. The order matters, and only one order is safe.
//
// The store is the only record naming which accounts hold broker-issued keys. It used
// to be emptied first, in its own loop over every key, before a single
// authorized_keys entry was touched. So a failure in the second loop — which the code
// already anticipates, audits as ORPHANED_KEYS_NOT_REMOVED, and continues past — left
// the entry in place with nothing left that could ever find it again. The next startup
// reconciles an empty store and does nothing; sweepExpiredAuthorizedKeys only reaches
// accounts with a session expiring now, and an orphan belongs to no session at all. A
// user who never logs in again keeps a working credential indefinitely, which is #171
// by a different route (#228).
func TestAFailedRemovalLeavesTheRecordThatFindsItAgain(t *testing.T) {
	env := newRevokeTestEnv(t)
	// Short enough that the contended account fails fast rather than holding the test
	// for the lock's default patience.
	env.broker.authorizedKeysManager.SetLockTimeout(150 * time.Millisecond)

	alice := env.provision(t, "alice")
	bob := env.provision(t, "bob")

	// Both accounts are authorized before the restart this simulates.
	for _, username := range []string{"alice", "bob"} {
		if got := env.authorizedKeys(t, username); !strings.Contains(got, "ssh-") {
			t.Fatalf("%s was not authorized to begin with; file is %q", username, got)
		}
	}

	// Stand in for the removal failing: alice's lock is held by someone else, so
	// RemoveOIDCKeys("alice") times out. This is the branch the old code already knew
	// could happen — it audits and continues — having already deleted alice's record.
	release := holdLock(t, env.broker, "alice")

	// No sessions: every stored key is an orphan, which is the startup state.
	env.broker.reconcileIssuedKeys()

	// bob's removal succeeded, so both halves are done for bob.
	if got := env.authorizedKeys(t, "bob"); strings.Contains(got, "ssh-") {
		t.Errorf("bob's orphaned entry survived a successful removal; file is %q", got)
	}
	if _, err := env.broker.keyManager.LoadKey(bob.SSHKeyID); err == nil {
		t.Error("bob's stored key record survived, though its entry was removed")
	}

	// alice's removal failed, so her entry is still there — that much is unavoidable.
	if got := env.authorizedKeys(t, "alice"); !strings.Contains(got, "ssh-") {
		t.Fatalf("alice's entry was removed while her lock was held; file is %q", got)
	}

	// This is the assertion. The record must still be there, because it is the only
	// thing that will bring the next startup back to alice.
	if _, err := env.broker.keyManager.LoadKey(alice.SSHKeyID); err != nil {
		t.Fatalf("alice's stored key record was deleted even though her authorized_keys "+
			"entry could not be removed: nothing now names her account, so no later "+
			"reconcile will ever revoke that key and it authorizes logins forever (%v)", err)
	}

	// And the retry actually works, which is the point of keeping the record.
	release()
	env.broker.reconcileIssuedKeys()

	if got := env.authorizedKeys(t, "alice"); strings.Contains(got, "ssh-") {
		t.Errorf("the retried reconcile did not remove alice's entry; file is %q", got)
	}
	if _, err := env.broker.keyManager.LoadKey(alice.SSHKeyID); err == nil {
		t.Error("alice's stored key record survived the retry that removed her entry")
	}
}

// holdLock takes the authorized_keys lock for an account and returns the release, so
// a test can drive both the failure and the retry that follows it. holdUsersLock in
// key_sweep_test.go releases only at cleanup, which cannot express a retry.
func holdLock(t *testing.T, broker *Broker, username string) func() {
	t.Helper()

	path := broker.authorizedKeysManager.LockPath(username)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	// flock is held per open file description, so this contends with the broker's own
	// open of the same path even though both are in this process — and it contends for
	// root too, which a permission-based failure would not.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("flock: %v", err)
	}

	var once sync.Once
	release := func() {
		once.Do(func() {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
		})
	}
	t.Cleanup(release)
	return release
}
