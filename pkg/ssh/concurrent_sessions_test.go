package ssh

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// (#227) An account gets one broker-issued entry per live session, not one entry
// full stop.
//
// What the single entry cost, on a host where nothing was misconfigured: a user
// logged in from their laptop and then from a jump host, and the second login's
// install removed the entry the laptop's session was using. The open connection
// carried on working, because sshd had already authenticated it, so the loss showed
// up later and somewhere else — the next `ssh` to the same host refused, a
// ControlMaster re-dial refused, the reconnect after closing a laptop lid refused —
// while the broker reported that session as live and unexpired and `CheckSession`
// agreed. Nothing in authorized_keys, the broker log or the audit trail recorded
// that the key had been taken away.
//
// The tests below pin both halves: concurrent logins each keep their key, and the
// number of them an account can hold is still bounded.

// liveBrokerEntry renders an entry of exactly the shape an install writes — the
// expiry-time= option that sshd enforces, in front of a key carrying the broker's
// marker — so that a planted file is one the broker could itself have produced.
func liveBrokerEntry(expiresAt time.Time, distinguisher string) string {
	return brokerEntryLine(brokerKeyLine(expiresAt.Add(-time.Hour), distinguisher), expiresAt)
}

// brokerComments counts the provenance comments in a file. One per broker-issued
// entry is right; more than that means an entry's comment outlived it and is now
// claiming a date for whichever entry follows it.
func brokerComments(content string) int {
	return strings.Count(content, brokerCommentPrefix)
}

// The failure the issue describes, in the smallest form that shows it: two logins,
// and afterwards both keys must authenticate.
func TestASecondLoginKeepsTheFirstSessionsKey(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	own := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5MINE personal-laptop"
	plantLines(t, baseDir, "testuser", own)

	laptop := brokerKeyLine(time.Now().Add(-time.Minute), "LAPTOP")
	jumphost := brokerKeyLine(time.Now(), "JUMPHOST")
	if err := akm.AddPublicKey("testuser", laptop, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("AddPublicKey (laptop): %v", err)
	}
	if err := akm.AddPublicKey("testuser", jumphost, time.Now().Add(2*time.Hour)); err != nil {
		t.Fatalf("AddPublicKey (jump host): %v", err)
	}

	oidcKeys, err := akm.ListOIDCKeys("testuser")
	if err != nil {
		t.Fatalf("ListOIDCKeys: %v", err)
	}
	if len(oidcKeys) != 2 {
		t.Errorf("the account holds %d broker-issued keys after two logins, want 2 — one per "+
			"live session: %q", len(oidcKeys), oidcKeys)
	}
	for name, key := range map[string][]byte{"laptop": laptop, "jump host": jumphost} {
		authorized, err := akm.KeyIsAuthorized("testuser", key)
		if err != nil {
			t.Fatalf("KeyIsAuthorized (%s): %v", name, err)
		}
		if !authorized {
			t.Errorf("the %s session's key no longer authorizes anything, so its next connection "+
				"— or a ControlMaster re-dial — is refused while the broker still calls the "+
				"session live (#227)", name)
		}
	}

	content := readKeys(t, baseDir, "testuser")
	if !strings.Contains(content, own) {
		t.Errorf("the user's own key was removed; the broker only owns its own entries. file is %q", content)
	}
	// One provenance comment per entry, not one per login: a comment left behind by an
	// entry that is gone would date the entry that happens to follow it.
	if got := brokerComments(content); got != 2 {
		t.Errorf("the file carries %d broker comments for 2 broker entries; file is %q", got, content)
	}

	// Each session's key is still revocable on its own — the property that made one
	// key per account seem safe in the first place, and it does not depend on there
	// being only one.
	removed, err := akm.RemovePublicKey("testuser", laptop)
	if err != nil {
		t.Fatalf("RemovePublicKey: %v", err)
	}
	if !removed {
		t.Error("revoking the laptop session's key matched nothing, so the revocation is a no-op")
	}
	after := readKeys(t, baseDir, "testuser")
	if strings.Contains(after, "LAPTOP") {
		t.Errorf("the revoked key still authorizes access; file is %q", after)
	}
	if !strings.Contains(after, "JUMPHOST") {
		t.Errorf("revoking one session's key took the other session's with it; file is %q", after)
	}
}

// Keeping the other sessions' keys must not become "keeping everything". An entry
// sshd has already stopped honouring has to go, whether or not the sweep
// (RemoveExpiredKeys) ever reaches this account — it only runs for a user who has a
// session expiring, so for a user whose sessions all ended with the broker that
// issued them, an install is the next thing that will look at the file.
func TestAnInstallStillDropsEntriesSSHDHasStoppedHonouring(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	own := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5MINE personal-laptop"
	plantLines(t, baseDir, "testuser",
		own,
		"# Added by OIDC PAM on 2026-01-01 00:00:00",
		// Expired by its own option, which is the form every current broker writes.
		liveBrokerEntry(time.Now().Add(-time.Minute), "EXPIREDBYOPTION"),
		"# Added by OIDC PAM on 2026-01-02 00:00:00",
		// No option at all: a pre-#171 broker's entry, dated only by its comment, and
		// older than the configured lifetime.
		string(brokerKeyLine(time.Now().Add(-48*time.Hour), "EXPIREDBYCOMMENT")),
		"# Added by OIDC PAM on 2026-01-03 00:00:00",
		liveBrokerEntry(time.Now().Add(time.Hour), "STILLLIVE"),
	)

	if err := akm.AddPublicKey("testuser", brokerKeyLine(time.Now(), "NEWLOGIN"), testExpiry()); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	content := readKeys(t, baseDir, "testuser")
	for _, gone := range []string{"EXPIREDBYOPTION", "EXPIREDBYCOMMENT"} {
		if strings.Contains(content, gone) {
			t.Errorf("%s survived an install although its expiry has passed; file is %q", gone, content)
		}
	}
	for _, want := range []string{"STILLLIVE", "NEWLOGIN", own} {
		if !strings.Contains(content, want) {
			t.Errorf("%s is missing after the install; file is %q", want, content)
		}
	}
	if got := brokerComments(content); got != 2 {
		t.Errorf("the file carries %d broker comments for 2 broker entries: the comments of the "+
			"expired entries outlived them. file is %q", got, content)
	}
}

// A key per session, with no bound, is a file that grows for as long as the account
// keeps logging in — and it does not merely get untidy. Past maxAuthorizedKeysBytes
// the broker refuses to read the file at all, and from then on it can neither
// provision a login nor sweep anything for that account.
func TestTheNumberOfLiveKeysAnAccountHoldsIsBounded(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	own := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5MINE personal-laptop"
	plantLines(t, baseDir, "testuser", own)

	// More logins than the limit, each with a later expiry than the last, as a user
	// logging in over and over produces.
	const logins = maxConcurrentOIDCKeys + 4
	for i := 0; i < logins; i++ {
		key := brokerKeyLine(time.Now(), fmt.Sprintf("LOGIN%02d", i))
		if err := akm.AddPublicKey("testuser", key, time.Now().Add(time.Duration(i+1)*time.Hour)); err != nil {
			t.Fatalf("AddPublicKey (login %d): %v", i, err)
		}
	}

	oidcKeys, err := akm.ListOIDCKeys("testuser")
	if err != nil {
		t.Fatalf("ListOIDCKeys: %v", err)
	}
	if len(oidcKeys) != maxConcurrentOIDCKeys {
		t.Errorf("%d logins left %d broker-issued keys, want the limit of %d",
			logins, len(oidcKeys), maxConcurrentOIDCKeys)
	}

	content := readKeys(t, baseDir, "testuser")
	// The newest login is the one that must work: it is the session the user is
	// sitting in front of.
	if !strings.Contains(content, fmt.Sprintf("LOGIN%02d", logins-1)) {
		t.Errorf("the most recent login's key is not in the file; file is %q", content)
	}
	// The oldest are the ones that go.
	for i := 0; i < logins-maxConcurrentOIDCKeys; i++ {
		if got := fmt.Sprintf("LOGIN%02d", i); strings.Contains(content, got) {
			t.Errorf("%s is still authorized although %d logins have happened since; file is %q",
				got, logins-i, content)
		}
	}
	if !strings.Contains(content, own) {
		t.Errorf("the user's own key was evicted; the limit applies to the broker's own entries "+
			"only. file is %q", content)
	}
	if got := brokerComments(content); got != maxConcurrentOIDCKeys {
		t.Errorf("the file carries %d broker comments for %d broker entries; file is %q",
			got, maxConcurrentOIDCKeys, content)
	}
}

// Which key the limit takes matters. The one nearest its expiry belongs to the
// session closest to ending anyway; taking the one with the longest left would cut
// short the session with the most use still in it.
func TestTheKeyNearestItsExpiryIsTheOneEvicted(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	// A full complement of live entries, planted out of order so that nothing can pass
	// this by evicting the first or the last line.
	lines := make([]string, 0, maxConcurrentOIDCKeys)
	for _, hours := range []int{5, 1, 9, 3, 7} {
		lines = append(lines, liveBrokerEntry(time.Now().Add(time.Duration(hours)*time.Hour),
			fmt.Sprintf("EXPIRESIN%02dH", hours)))
	}
	for i := len(lines); i < maxConcurrentOIDCKeys; i++ {
		lines = append(lines, liveBrokerEntry(time.Now().Add(time.Duration(24+i)*time.Hour),
			fmt.Sprintf("FILLER%02d", i)))
	}
	plantLines(t, baseDir, "testuser", lines...)

	if err := akm.AddPublicKey("testuser", brokerKeyLine(time.Now(), "NEWLOGIN"), testExpiry()); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	content := readKeys(t, baseDir, "testuser")
	if strings.Contains(content, "EXPIRESIN01H") {
		t.Errorf("the entry with the least time left was kept, so something else was evicted "+
			"instead; file is %q", content)
	}
	for _, hours := range []int{3, 5, 7, 9} {
		if want := fmt.Sprintf("EXPIRESIN%02dH", hours); !strings.Contains(content, want) {
			t.Errorf("%s was evicted although an entry expiring sooner was available; file is %q",
				want, content)
		}
	}
	if !strings.Contains(content, "NEWLOGIN") {
		t.Errorf("the login that caused the eviction did not get its own key; file is %q", content)
	}
}

// An entry carrying the broker's marker whose expiry cannot be read either way is the
// first to go when the limit is reached. RemoveExpiredKeys retains such an entry
// deliberately — cleanup fails safe, never early — so if it were also preferred to
// keys known to be live, a handful of mangled lines (the #165 fusion left exactly
// these) would hold the limit for good and evict every real session's key instead.
func TestAnEntryWhoseExpiryCannotBeReadIsEvictedFirst(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	// Broker-marked, so it is the broker's to manage, but with nothing in it that says
	// when it stops working.
	const undatable = "ssh-rsa AAAAB3NzaC1yc2EUNDATABLE testuser@oidc-pam-not-a-timestamp"
	lines := []string{undatable}
	for i := len(lines); i < maxConcurrentOIDCKeys; i++ {
		lines = append(lines, liveBrokerEntry(time.Now().Add(time.Duration(i+1)*time.Hour),
			fmt.Sprintf("LIVE%02d", i)))
	}
	plantLines(t, baseDir, "testuser", lines...)

	if err := akm.AddPublicKey("testuser", brokerKeyLine(time.Now(), "NEWLOGIN"), testExpiry()); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	content := readKeys(t, baseDir, "testuser")
	if strings.Contains(content, "UNDATABLE") {
		t.Errorf("an entry with no readable expiry was kept in preference to a key known to be "+
			"live; file is %q", content)
	}
	if !strings.Contains(content, "LIVE01") {
		t.Errorf("a live session's key was evicted while an entry the broker cannot date stayed; "+
			"file is %q", content)
	}
}
