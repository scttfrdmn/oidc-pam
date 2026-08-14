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

	for _, key := range [][]byte{
		brokerKeyLine(time.Now().Add(-48*time.Hour), "STALE"),
		brokerKeyLine(time.Now().Add(-time.Hour), "FRESH"),
	} {
		if err := akm.AddPublicKey("testuser", key); err != nil {
			t.Fatalf("AddPublicKey: %v", err)
		}
	}

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

	doomed := brokerKeyLine(time.Now(), "DOOMED")
	keeper := brokerKeyLine(time.Now(), "KEEPER")
	for _, key := range [][]byte{doomed, keeper} {
		if err := akm.AddPublicKey("testuser", key); err != nil {
			t.Fatalf("AddPublicKey: %v", err)
		}
	}

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

	stale := brokerKeyLine(time.Now().Add(-48*time.Hour), "STALE")
	surviving := brokerKeyLine(time.Now().Add(-time.Hour), "SURVIVING")
	for _, key := range [][]byte{stale, surviving} {
		if err := akm.AddPublicKey("testuser", key); err != nil {
			t.Fatalf("AddPublicKey: %v", err)
		}
	}

	if err := akm.RemoveExpiredKeys("testuser"); err != nil {
		t.Fatalf("RemoveExpiredKeys: %v", err)
	}

	// The next login, appending to whatever the sweep left behind.
	nextLogin := brokerKeyLine(time.Now(), "NEXTLOGIN")
	if err := akm.AddPublicKey("testuser", nextLogin); err != nil {
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

	// Both keys must still be revocable — the point of the whole exercise.
	for _, key := range [][]byte{surviving, nextLogin} {
		removed, err := akm.RemovePublicKey("testuser", key)
		if err != nil {
			t.Fatalf("RemovePublicKey: %v", err)
		}
		if !removed {
			t.Errorf("no authorized_keys line matched %q, so revoking it is a no-op", key)
		}
		if got := readKeys(t, baseDir, "testuser"); strings.Contains(got, string(key)) {
			t.Errorf("key %q still authorizes access after revocation", key)
		}
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
	if err := akm.AddPublicKey("testuser", newKey); err != nil {
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
