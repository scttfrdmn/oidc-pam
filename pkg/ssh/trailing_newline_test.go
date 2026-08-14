package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// brokerKeyLine builds an authorized_keys entry of the shape the broker issues:
// the `@oidc-pam-<unix>` comment is what RemoveExpiredKeys reads to decide whether
// the key is stale.
func brokerKeyLine(issuedAt time.Time, distinguisher string) []byte {
	return []byte(fmt.Sprintf("ssh-rsa AAAAB3NzaC1yc2E%s testuser@oidc-pam-%d",
		distinguisher, issuedAt.Unix()))
}

// plantLines writes authorized_keys directly, so a test can set up a state a
// previous broker left behind.
//
// AddPublicKey cannot be used for this: it writes each entry with the expiry it is
// given and a comment stamped with the moment of the call, so a file holding an entry
// a previous broker left behind — expired, undatable, or written before
// `expiry-time=` existed — is not a file any sequence of installs can produce.
func plantLines(t *testing.T, baseDir, username string, lines ...string) {
	t.Helper()

	sshDir := filepath.Join(baseDir, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("MkdirAll %s: %v", sshDir, err)
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// readKeys returns a user's authorized_keys contents verbatim — trailing newline
// included, which is the whole subject of these tests.
func readKeys(t *testing.T, baseDir, username string) string {
	t.Helper()

	path := filepath.Join(baseDir, username, ".ssh", "authorized_keys")
	data, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	return string(data)
}

// fusedLines returns the lines that hold a key and a broker comment at once. Such
// a line is the #165 defect made visible: sshd would still honour the key part,
// and neither remover can ever match the line again.
func fusedLines(content string) []string {
	var fused []string
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "# Added by OIDC PAM") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			fused = append(fused, line)
		}
	}
	return fused
}

// The rewritten file must end in a newline. authorized_keys is append-only for
// every writer that touches it, so an unterminated last line is not cosmetic: the
// next append lands on it (#165).
func TestExpirySweepLeavesATrailingNewline(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	plantLines(t, baseDir, "testuser",
		string(brokerKeyLine(time.Now().Add(-48*time.Hour), "STALE")),
		string(brokerKeyLine(time.Now().Add(-time.Hour), "FRESH")))

	if err := akm.RemoveExpiredKeys("testuser"); err != nil {
		t.Fatalf("RemoveExpiredKeys: %v", err)
	}

	content := readKeys(t, baseDir, "testuser")
	if content == "" {
		t.Fatal("the sweep emptied a file that still had a fresh key in it")
	}
	if !strings.HasSuffix(content, "\n") {
		t.Errorf("the swept file does not end in a newline, so the next AddPublicKey will "+
			"append onto its last key line (#165); tail is %q", tail(content))
	}
	if strings.HasSuffix(content, "\n\n") {
		t.Errorf("the swept file gained a blank line at the end; tail is %q", tail(content))
	}
}

// Same requirement for the targeted-removal path. It happened to be correct
// (strings.Split keeps the trailing empty element), and now that both paths share
// one writer this is what stops that from regressing.
func TestTargetedRemovalLeavesATrailingNewline(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	// The survivor is the user's own key, which is what a targeted removal must
	// preserve whatever else the file holds: the broker's own entries come and go with
	// the sessions they belong to, and this key does not.
	doomed := brokerKeyLine(time.Now(), "DOOMED")
	keeper := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5KEEPER personal-laptop"
	plantLines(t, baseDir, "testuser", string(doomed), keeper)

	removed, err := akm.RemovePublicKey("testuser", doomed)
	if err != nil {
		t.Fatalf("RemovePublicKey: %v", err)
	}
	if !removed {
		t.Fatal("RemovePublicKey reported no match for a key it had just added")
	}

	content := readKeys(t, baseDir, "testuser")
	if !strings.HasSuffix(content, "\n") {
		t.Errorf("the rewritten file does not end in a newline (#165); tail is %q", tail(content))
	}
}

// The sequence from #165, with no attacker in it: a sweep removes an expired key,
// the user logs in again, and the login's comment lands on the last surviving key
// line — making that entry both permanently authorized and permanently
// irremovable. This drives the whole cycle and insists the last step really
// revokes.
func TestAddSweepAddRevokeRoundTrip(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	// The survivor is the user's own key, so the file the sweep leaves behind for the
	// next login to write into ends in a line the broker does not own — which is what
	// made the fused line of #165 both permanent and irremovable.
	stale := brokerKeyLine(time.Now().Add(-48*time.Hour), "STALE")
	surviving := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5SURVIVING personal-laptop"
	plantLines(t, baseDir, "testuser", string(stale), surviving)

	if err := akm.RemoveExpiredKeys("testuser"); err != nil {
		t.Fatalf("RemoveExpiredKeys: %v", err)
	}

	// The next login, writing over whatever the sweep left behind.
	nextLogin := brokerKeyLine(time.Now(), "NEXTLOGIN")
	if err := akm.AddPublicKey("testuser", nextLogin, testExpiry()); err != nil {
		t.Fatalf("AddPublicKey after the sweep: %v", err)
	}

	content := readKeys(t, baseDir, "testuser")
	if fused := fusedLines(content); len(fused) > 0 {
		t.Errorf("a key line was fused with the login comment appended after the sweep, "+
			"so that key can never be revoked again (#165): %q", fused)
	}
	for _, want := range []string{"SURVIVING", "NEXTLOGIN"} {
		if !strings.Contains(content, want) {
			t.Errorf("%s key is missing from authorized_keys after the round trip", want)
		}
	}
	if strings.Contains(content, "STALE") {
		t.Error("the expired key survived the sweep")
	}

	// The broker's key must still be revocable — the point of the whole exercise.
	removed, err := akm.RemovePublicKey("testuser", nextLogin)
	if err != nil {
		t.Fatalf("RemovePublicKey: %v", err)
	}
	if !removed {
		t.Errorf("no authorized_keys line matched %q, so revoking it is a no-op", nextLogin)
	}
	after := readKeys(t, baseDir, "testuser")
	if strings.Contains(after, "NEXTLOGIN") {
		t.Errorf("key %q still authorizes access after revocation", nextLogin)
	}
	if !strings.Contains(after, surviving) {
		t.Errorf("revocation removed the user's own key; file is %q", after)
	}
}

// Every login used to leave another `@oidc-pam-` entry behind, deduplicated only
// against a byte-identical line — which the issue timestamp in the comment made
// impossible. A user who logged in daily therefore accumulated one permanently
// valid key per login, each on its own sufficient to authenticate, so revoking the
// current session's key left all the earlier ones working (#171).
//
// What that accumulation is bounded by is now the expiry on each entry and the
// per-account limit, not the removal of keys that other sessions are still using
// (#227, and TestASecondLoginKeepsTheFirstSessionsKey). What this test keeps is the
// file hygiene across repeated logins: whatever the broker keeps, no line may be fused
// with a comment, no line may be duplicated, and the user's own key is not the
// broker's to touch.
func TestRepeatedLoginsLeaveAWellFormedFile(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	own := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5MINE personal-laptop"
	plantLines(t, baseDir, "testuser", own)

	first := brokerKeyLine(time.Now().Add(-time.Minute), "FIRSTLOGIN")
	second := brokerKeyLine(time.Now(), "SECONDLOGIN")
	for _, key := range [][]byte{first, second, second} {
		if err := akm.AddPublicKey("testuser", key, testExpiry()); err != nil {
			t.Fatalf("AddPublicKey: %v", err)
		}
	}

	content := readKeys(t, baseDir, "testuser")
	if fused := fusedLines(content); len(fused) > 0 {
		t.Errorf("a key line was fused with a login comment, so that key can never be revoked "+
			"again (#165): %q", fused)
	}
	if !strings.HasSuffix(content, "\n") || strings.HasSuffix(content, "\n\n") {
		t.Errorf("the file does not end in exactly one newline; tail is %q", tail(content))
	}
	// Re-installing the same entry replaces it rather than adding a second copy: a
	// duplicate would survive the revocation of the one the broker knows about.
	if got := strings.Count(content, "SECONDLOGIN"); got != 1 {
		t.Errorf("the third install left %d copies of the same entry, not 1; file is %q", got, content)
	}
	oidcKeys, err := akm.ListOIDCKeys("testuser")
	if err != nil {
		t.Fatalf("ListOIDCKeys: %v", err)
	}
	if len(oidcKeys) != 2 {
		t.Errorf("three installs of two distinct keys left %d broker-issued entries, want 2: %q",
			len(oidcKeys), oidcKeys)
	}
	if !strings.Contains(content, own) {
		t.Errorf("the user's own key was removed; the broker only owns its own entries. file is %q", content)
	}
	// One provenance comment per entry, not one per login.
	if got := strings.Count(content, "# Added by OIDC PAM on"); got != len(oidcKeys) {
		t.Errorf("authorized_keys carries %d broker comments for %d broker entries; file is %q",
			got, len(oidcKeys), content)
	}
}

// sshd must be able to expire the key without the broker's help. Everything that
// was supposed to remove a stale entry ran inside the broker — sessions in memory,
// a sweep on a timer — so a restart, or simply a broker that never got round to it,
// left a working credential (#171).
func TestInstalledEntryCarriesTheExpirySSHDEnforces(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	expiresAt := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
	key := brokerKeyLine(time.Now(), "EXPIRY")
	if err := akm.AddPublicKey("testuser", key, expiresAt); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	// The timespec is the unsuffixed 14-digit form, which is what every sshd that knows
	// the option parses; TestTheExpiryTimespecIsTheFormEverySupportedSSHDParses covers
	// why it is not the UTC one, and the #226 tests cover the offset it is rendered at.
	//
	// The expectation is not expiresAt.Local(): the entry is rendered at the zone's
	// *standard* offset, because that is the offset sshd's parse_absolute_time resolves
	// an unsuffixed timespec at whatever the time of year (#226). Asserting the local
	// rendering made this test's result depend on the time zone of the machine running
	// it — it passed in UTC and in a northern-hemisphere winter, and failed for a March
	// expiry anywhere south of the equator, an hour of drift that says nothing about
	// the code. What is checked here is that the installed line carries the option at
	// all, and that its value is the digits-only form.
	content := readKeys(t, baseDir, "testuser")
	want := fmt.Sprintf(`expiry-time=%q`, formatExpiryTimespec(expiresAt))
	if !strings.Contains(content, want) {
		t.Errorf("authorized_keys does not carry %s; file is %q", want, content)
	}
	if timespec := formatExpiryTimespec(expiresAt); len(timespec) != 14 || strings.Trim(timespec, "0123456789") != "" {
		t.Errorf("the timespec written is %q, not the 14 digits every supported sshd parses", timespec)
	}

	// And the option must be read back as the expiry it states, or the sweep cannot
	// act on it.
	oidcKeys, err := akm.ListOIDCKeys("testuser")
	if err != nil {
		t.Fatalf("ListOIDCKeys: %v", err)
	}
	if len(oidcKeys) != 1 {
		t.Fatalf("expected 1 broker key, got %d: %q", len(oidcKeys), oidcKeys)
	}
	entry, ok := parseKeyEntry(oidcKeys[0])
	if !ok {
		t.Fatalf("the installed entry does not parse: %q", oidcKeys[0])
	}
	parsed, ok := entry.expiryTime()
	if !ok {
		t.Fatalf("the installed entry's expiry-time cannot be read back: %q", oidcKeys[0])
	}
	if !parsed.Equal(expiresAt) {
		t.Errorf("expiry read back as %s, want %s", parsed, expiresAt)
	}
}

// An expiry that has already passed, or none at all, is not something to write into
// a key list in the hope that something removes it later.
func TestAddPublicKeyRefusesAnExpiryThatIsNotInTheFuture(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)
	key := brokerKeyLine(time.Now(), "BADEXPIRY")

	for name, expiry := range map[string]time.Time{
		"zero": {},
		"past": time.Now().Add(-time.Minute),
	} {
		if err := akm.AddPublicKey("testuser", key, expiry); err == nil {
			t.Errorf("AddPublicKey accepted a %s expiry", name)
		}
	}
	if _, err := os.Stat(filepath.Join(baseDir, "testuser", ".ssh", "authorized_keys")); err == nil {
		t.Error("a key was installed despite the expiry being refused")
	}
}

// The sweep must honour the configured lifetime. It used to compare against a
// hardcoded 24 hours whatever the site had configured, so a deployment that had
// deliberately set token_lifetime: 1h still left every key it issued usable for a
// day (#171).
func TestSweepUsesTheConfiguredLifetimeForOlderEntries(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)
	akm.SetKeyLifetime(time.Hour)

	// Entries as an older broker wrote them: no expiry-time= option, only the issue
	// time in the comment.
	pastLifetime := brokerKeyLine(time.Now().Add(-2*time.Hour), "PASTLIFETIME")
	withinLifetime := brokerKeyLine(time.Now().Add(-10*time.Minute), "WITHINLIFETIME")
	plantLines(t, baseDir, "testuser", string(pastLifetime), string(withinLifetime))

	if err := akm.RemoveExpiredKeys("testuser"); err != nil {
		t.Fatalf("RemoveExpiredKeys: %v", err)
	}

	content := readKeys(t, baseDir, "testuser")
	if strings.Contains(content, "PASTLIFETIME") {
		t.Error("a key issued two hours ago survived a sweep with a one-hour configured lifetime, " +
			"so the configured lifetime is not what the sweep measures against")
	}
	if !strings.Contains(content, "WITHINLIFETIME") {
		t.Error("a key issued ten minutes ago was swept under a one-hour lifetime")
	}
}

// An entry carrying options must still be recognised by the sweep. The timestamp
// used to be read out of strings.Fields(line)[2], which is the key data rather than
// the comment once anything precedes the key type — so the sweep would silently
// have stopped recognising the broker's own entries (#171).
func TestSweepReadsEntriesThatCarryOptions(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	expired := fmt.Sprintf(`expiry-time="%s" %s`,
		time.Now().Add(-time.Minute).UTC().Format("20060102150405Z"),
		brokerKeyLine(time.Now(), "OPTIONEXPIRED"))
	live := fmt.Sprintf(`expiry-time="%s" %s`,
		time.Now().Add(time.Hour).UTC().Format("20060102150405Z"),
		brokerKeyLine(time.Now(), "OPTIONLIVE"))
	plantLines(t, baseDir, "testuser", expired, live)

	if err := akm.RemoveExpiredKeys("testuser"); err != nil {
		t.Fatalf("RemoveExpiredKeys: %v", err)
	}

	content := readKeys(t, baseDir, "testuser")
	if strings.Contains(content, "OPTIONEXPIRED") {
		t.Error("an entry whose expiry-time= has passed survived the sweep")
	}
	if !strings.Contains(content, "OPTIONLIVE") {
		t.Error("an entry whose expiry-time= is in the future was swept")
	}
}

// Removal has to match the entry the broker itself wrote, which now carries an
// expiry-time= option in front of the key while the broker holds only the bare key
// in its store. Comparing whole lines would never match again (#171).
func TestRemovalMatchesAnEntryThatCarriesOptions(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	key := brokerKeyLine(time.Now(), "OPTIONREMOVE")
	if err := akm.AddPublicKey("testuser", key, testExpiry()); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	removed, err := akm.RemovePublicKey("testuser", key)
	if err != nil {
		t.Fatalf("RemovePublicKey: %v", err)
	}
	if !removed {
		t.Fatal("RemovePublicKey found no match for the entry it had just installed, " +
			"so revoking a key is a no-op the broker reports as a success")
	}
	authorized, err := akm.KeyIsAuthorized("testuser", key)
	if err != nil {
		t.Fatalf("KeyIsAuthorized: %v", err)
	}
	if authorized {
		t.Error("the key still authorizes access after removal")
	}
}

// RemoveOIDCKeys is what makes a broker restart safe: the broker has no session for
// the keys it issued before it stopped, so the only way to revoke them is to remove
// every entry bearing its marker.
func TestRemoveOIDCKeysClearsOrphansAndKeepsTheUsersOwn(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	own := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5OWN personal-laptop"
	plantLines(t, baseDir, "testuser",
		"# Added by OIDC PAM on 2025-01-01 00:00:00",
		string(brokerKeyLine(time.Now().Add(-time.Hour), "ORPHANA")),
		fmt.Sprintf(`expiry-time="%s" %s`,
			time.Now().Add(time.Hour).UTC().Format("20060102150405Z"),
			brokerKeyLine(time.Now(), "ORPHANB")),
		own)

	removed, err := akm.RemoveOIDCKeys("testuser")
	if err != nil {
		t.Fatalf("RemoveOIDCKeys: %v", err)
	}
	if removed != 2 {
		t.Errorf("RemoveOIDCKeys removed %d entries, want 2", removed)
	}

	content := readKeys(t, baseDir, "testuser")
	for _, gone := range []string{"ORPHANA", "ORPHANB"} {
		if strings.Contains(content, gone) {
			t.Errorf("orphaned key %s still authorizes access; file is %q", gone, content)
		}
	}
	if !strings.Contains(content, own) {
		t.Errorf("the user's own key was removed; file is %q", content)
	}
	// A comment claiming the broker added a key it has just revoked misleads the next
	// reader of the file.
	if strings.Contains(content, "# Added by OIDC PAM on") {
		t.Errorf("a stranded broker comment was left behind; file is %q", content)
	}
}

// A file some other writer left unterminated — the user's own editor, or a broker
// from before this fix — must not turn the next login into a fused line either.
func TestAddPublicKeyTerminatesAnUnterminatedFile(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	sshDir := filepath.Join(baseDir, "testuser", ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	existing := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 personal-laptop"
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(existing), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	newKey := brokerKeyLine(time.Now(), "NEWKEY")
	if err := akm.AddPublicKey("testuser", newKey, testExpiry()); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	content := readKeys(t, baseDir, "testuser")
	if fused := fusedLines(content); len(fused) > 0 {
		t.Errorf("appending to an unterminated file fused a comment onto a key line (#165): %q", fused)
	}
	// The user's own key is not the broker's to rewrite, only to terminate.
	if !strings.Contains(content, existing) {
		t.Errorf("the user's own key was mangled; file is %q", content)
	}
	removed, err := akm.RemovePublicKey("testuser", newKey)
	if err != nil {
		t.Fatalf("RemovePublicKey: %v", err)
	}
	if !removed {
		t.Error("the key added to an unterminated file cannot be revoked")
	}
}

// tail returns the last few bytes of s, for failure messages about a file's end.
func tail(s string) string {
	const n = 40
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
