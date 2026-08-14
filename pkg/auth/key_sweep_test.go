package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
	sshpkg "github.com/scttfrdmn/oidc-pam/pkg/ssh"
)

// testAuthorizedKeysManager returns an AuthorizedKeysManager that resolves homes
// under homeDir, and creates the home directories of the named accounts.
//
// (#171) The manager no longer takes a base directory: it resolves each account's
// home through the account database, and refuses a home that does not exist rather
// than creating one as root. Tests substitute the lookup instead of creating real
// accounts on the machine running the suite.
func testAuthorizedKeysManager(t *testing.T, homeDir string, usernames ...string) *sshpkg.AuthorizedKeysManager {
	t.Helper()

	for _, username := range usernames {
		if err := os.MkdirAll(filepath.Join(homeDir, username), 0700); err != nil {
			t.Fatalf("MkdirAll home for %s: %v", username, err)
		}
	}
	akm := sshpkg.NewAuthorizedKeysManager(t.TempDir())
	akm.SetAccountLookup(sshpkg.HomeRootLookup(homeDir))
	return akm
}

// newSweepTestBroker returns a broker whose AuthorizedKeysManager is rooted at a
// temporary directory standing in for /home.
func newSweepTestBroker(t *testing.T) (*Broker, string) {
	t.Helper()

	homeDir := t.TempDir()

	auditLogger, err := security.NewAuditLogger(config.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	broker := &Broker{
		config: &config.Config{
			Authentication: config.AuthenticationConfig{TokenLifetime: time.Hour},
		},
		sessions:              make(map[string]*Session),
		sessionMutex:          sync.RWMutex{},
		providers:             map[string]*OIDCProvider{},
		auditLogger:           auditLogger,
		authorizedKeysManager: testAuthorizedKeysManager(t, homeDir),
	}

	return broker, homeDir
}

// writeAuthorizedKeys seeds a user's authorized_keys with the given lines.
func writeAuthorizedKeys(t *testing.T, homeDir, username string, lines ...string) string {
	t.Helper()

	sshDir := filepath.Join(homeDir, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	path := filepath.Join(sshDir, "authorized_keys")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func readAuthorizedKeys(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(data)
}

// oidcKeyLine builds a broker-style authorized_keys entry stamped with an issue
// time, which is what RemoveExpiredKeys reads to decide whether a key is stale.
func oidcKeyLine(issuedAt time.Time, distinguisher string) string {
	return fmt.Sprintf("ssh-rsa AAAAB3NzaC1yc2E%s testuser@oidc-pam-%d",
		distinguisher, issuedAt.Unix())
}

// The point of the change: an orphaned key — one issued by a broker that has
// since restarted, so no session remains to revoke it — is a working credential
// sitting in authorized_keys. RemoveExpiredKeys existed to remove those and was
// never called from anywhere.
func TestExpiringASessionSweepsOrphanedKeys(t *testing.T) {
	broker, homeDir := newSweepTestBroker(t)

	orphan := oidcKeyLine(time.Now().Add(-48*time.Hour), "ORPHAN")
	fresh := oidcKeyLine(time.Now().Add(-1*time.Hour), "FRESH")
	userOwned := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 personal-laptop"

	path := writeAuthorizedKeys(t, homeDir, "testuser", orphan, fresh, userOwned)

	broker.setSession(&Session{
		ID:           "sess-expired",
		UserID:       "testuser",
		ExpiresAt:    time.Now().Add(-time.Minute),
		LastAccessed: time.Now(),
	})

	broker.expireSessions(time.Now())

	remaining := readAuthorizedKeys(t, path)
	if strings.Contains(remaining, "ORPHAN") {
		t.Error("the expired orphaned key is still authorized")
	}
	if !strings.Contains(remaining, "FRESH") {
		t.Error("a key issued an hour ago was removed; only expired keys should be")
	}
	// The user's own keys are not the broker's to delete.
	if !strings.Contains(remaining, userOwned) {
		t.Error("the user's own key was removed from authorized_keys")
	}
}

// A live session's user must not be swept: the sweep is driven by expiry, and
// touching an unrelated user's file is how a maintenance pass becomes an outage.
func TestLiveSessionsDoNotTriggerASweep(t *testing.T) {
	broker, homeDir := newSweepTestBroker(t)

	stale := oidcKeyLine(time.Now().Add(-48*time.Hour), "STALE")
	path := writeAuthorizedKeys(t, homeDir, "activeuser", stale)

	broker.setSession(&Session{
		ID:           "sess-live",
		UserID:       "activeuser",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastAccessed: time.Now(),
	})

	broker.expireSessions(time.Now())

	if !strings.Contains(readAuthorizedKeys(t, path), "STALE") {
		t.Error("a user with only live sessions had their authorized_keys rewritten")
	}
}

// Several expired sessions for one user are one sweep, not one per session: the
// pass rewrites the file under a lock, and repeating it is wasted work.
func TestSweepRunsOncePerUser(t *testing.T) {
	broker, homeDir := newSweepTestBroker(t)

	path := writeAuthorizedKeys(t, homeDir, "busyuser",
		oidcKeyLine(time.Now().Add(-72*time.Hour), "OLD1"),
		oidcKeyLine(time.Now().Add(-48*time.Hour), "OLD2"),
	)

	for i := 0; i < 3; i++ {
		broker.setSession(&Session{
			ID:           fmt.Sprintf("sess-%d", i),
			UserID:       "busyuser",
			ExpiresAt:    time.Now().Add(-time.Minute),
			LastAccessed: time.Now(),
		})
	}

	broker.expireSessions(time.Now())

	remaining := readAuthorizedKeys(t, path)
	for _, marker := range []string{"OLD1", "OLD2"} {
		if strings.Contains(remaining, marker) {
			t.Errorf("expired key %s is still authorized", marker)
		}
	}
}

// A user whose authorized_keys does not exist is the normal state for a user who
// has never logged in over SSH, and a sweep failure must not stop the rest of the
// expiry work.
func TestSweepToleratesMissingAuthorizedKeys(t *testing.T) {
	broker, homeDir := newSweepTestBroker(t)

	path := writeAuthorizedKeys(t, homeDir, "haskeys",
		oidcKeyLine(time.Now().Add(-48*time.Hour), "OLD"))

	// "nohome" has no home directory at all; an invalid username exercises the
	// validation-error path.
	for _, userID := range []string{"nohome", "../../etc", ""} {
		broker.setSession(&Session{
			ID:           "sess-" + userID,
			UserID:       userID,
			ExpiresAt:    time.Now().Add(-time.Minute),
			LastAccessed: time.Now(),
		})
	}
	broker.setSession(&Session{
		ID:           "sess-haskeys",
		UserID:       "haskeys",
		ExpiresAt:    time.Now().Add(-time.Minute),
		LastAccessed: time.Now(),
	})

	broker.expireSessions(time.Now())

	if strings.Contains(readAuthorizedKeys(t, path), "OLD") {
		t.Error("a failing sweep for one user prevented the sweep for another")
	}
	if len(broker.ListSessions()) != 0 {
		t.Errorf("%d sessions survived expiry", len(broker.ListSessions()))
	}
}

// holdUsersLock takes the broker's authorized_keys lock for username and holds it
// until the test ends, standing in for a competing writer.
//
// Before #161 this lock lived in the user's own ~/.ssh, so the "competing writer"
// could be the user: `flock ~/.ssh/authorized_keys.lock -c 'sleep infinity'` and
// the broker's single cleanup goroutine never ran again.
func holdUsersLock(t *testing.T, broker *Broker, username string) {
	t.Helper()

	path := broker.authorizedKeysManager.LockPath(username)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	// flock is held per open file description, so this contends with the broker's
	// own open of the same path even though both are in this process.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("flock: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	})
}

// runExpiryWithin runs the expiry pass and fails the test if it has not finished
// by limit, rather than letting the package hang until the go test timeout.
func runExpiryWithin(t *testing.T, limit time.Duration, broker *Broker) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		broker.expireSessions(time.Now())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("expireSessions did not finish within %s; the cleanup goroutine is wedged (#161)", limit)
	}
}

// The whole of #161: one account holding its own lock must not stop the expiry
// pass, because there is exactly one cleanup goroutine for the host.
func TestSweepSurvivesAnUncooperativeLockHolder(t *testing.T) {
	broker, homeDir := newSweepTestBroker(t)
	broker.authorizedKeysManager.SetLockTimeout(150 * time.Millisecond)

	alicePath := writeAuthorizedKeys(t, homeDir, "alice",
		oidcKeyLine(time.Now().Add(-48*time.Hour), "ALICEOLD"))
	bobPath := writeAuthorizedKeys(t, homeDir, "bob",
		oidcKeyLine(time.Now().Add(-48*time.Hour), "BOBOLD"))

	holdUsersLock(t, broker, "alice")

	for _, user := range []string{"alice", "bob"} {
		broker.setSession(&Session{
			ID:           "sess-" + user,
			UserID:       user,
			ExpiresAt:    time.Now().Add(-time.Minute),
			LastAccessed: time.Now(),
		})
	}

	runExpiryWithin(t, 5*time.Second, broker)

	if strings.Contains(readAuthorizedKeys(t, bobPath), "BOBOLD") {
		t.Error("bob's expired key survived because alice was holding her lock")
	}
	// alice's own key is left for a later pass: the sweep is best-effort, and
	// writing without the lock would be worse than deferring.
	if !strings.Contains(readAuthorizedKeys(t, alicePath), "ALICEOLD") {
		t.Error("alice's authorized_keys was rewritten without holding the lock")
	}
	// Session expiry is the authoritative revocation and must not be held hostage
	// to a file write.
	if n := len(broker.ListSessions()); n != 0 {
		t.Errorf("%d sessions survived expiry while a lock was held", n)
	}
}

// Stop() waits on the cleanup goroutine, so a wedged sweep turned `systemctl
// restart oidc-auth-broker` into a 90-second wait for SIGKILL.
//
// This drives the two statements of Stop() that can block — close(stopChan) then
// wg.Wait() — around a sweep running under a held lock. It does not call Stop()
// itself: the rest of Stop() shuts down the token manager and audit logger, which
// have nothing to do with the lock and need a network-backed broker to construct.
func TestStopIsNotBlockedByAHeldLock(t *testing.T) {
	broker, homeDir := newSweepTestBroker(t)
	broker.authorizedKeysManager.SetLockTimeout(150 * time.Millisecond)
	broker.stopChan = make(chan struct{})

	writeAuthorizedKeys(t, homeDir, "alice",
		oidcKeyLine(time.Now().Add(-48*time.Hour), "ALICEOLD"))
	holdUsersLock(t, broker, "alice")

	broker.setSession(&Session{
		ID:           "sess-alice",
		UserID:       "alice",
		ExpiresAt:    time.Now().Add(-time.Minute),
		LastAccessed: time.Now(),
	})

	broker.wg.Add(1)
	go func() {
		defer broker.wg.Done()
		broker.expireSessions(time.Now())
	}()

	stopped := make(chan struct{})
	go func() {
		close(broker.stopChan)
		broker.wg.Wait()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not complete while a user held their lock; Stop() would hang until SIGKILL (#161)")
	}
}

// The broker is constructed without an AuthorizedKeysManager in several tests and
// in any deployment where key management is not in use.
func TestSweepWithoutAnAuthorizedKeysManager(t *testing.T) {
	broker, _ := newSweepTestBroker(t)
	broker.authorizedKeysManager = nil

	broker.setSession(&Session{
		ID:           "sess-expired",
		UserID:       "testuser",
		ExpiresAt:    time.Now().Add(-time.Minute),
		LastAccessed: time.Now(),
	})

	broker.expireSessions(time.Now()) // must not panic

	if broker.getSession("sess-expired") != nil {
		t.Error("expired session was not removed")
	}
}
