package ssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// (#228, item 3) The invariant these tests pin is the one the issue asks for: an
// account's authorized_keys is only ever *replaced* by a complete, correct set of
// lines, and a write that cannot complete leaves the previous complete set exactly
// where it was.
//
// What the defect looked like on a real host, before every rewrite path in this
// package went through the one atomic replace: reconciliation removed the stale
// managed entries and then wrote the current set, so between the two the file held
// neither. A login landing in that window was refused — the user was authenticated
// and then told `Permission denied (publickey)` — and if the process died or the
// second write failed, the account stayed that way until something reconciled it
// again, which for a user who does not log in again is never.
//
// The remaining half of item 3 is the *ordering of the two calls the broker makes*,
// which lives in pkg/auth/broker.go's reconcileIssuedKeys and cannot be fixed from
// this package: nothing here can make a caller's two operations one. What this
// package owes that fix is the guarantee below — that each single call it exposes is
// all-or-nothing — so that correct ordering above is sufficient.

// planted is a key list a previous broker and a user between them left behind: the
// user's own key, the broker's provenance comment, and one broker-issued entry.
func plantedKeyList(t *testing.T, baseDir string) string {
	t.Helper()

	plantLines(t, baseDir, "testuser",
		"ssh-rsa AAAAB3NzaC1yc2EOWNKEY testuser@laptop",
		"# Added by OIDC PAM on 2026-01-01 00:00:00",
		string(brokerKeyLine(time.Now().Add(-time.Hour), "BROKERKEY")),
	)
	return readKeys(t, baseDir, "testuser")
}

// makeUnwritable takes write permission off the .ssh directory, which is what makes
// the atomic replace fail: it cannot create its temp file there. This is the failure
// injection the issue asks for — "inject a failure between the remove and the add" —
// applied to the single call that now does both.
func makeUnwritable(t *testing.T, baseDir string) {
	t.Helper()

	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the directory mode this test needs")
	}
	sshDir := filepath.Join(baseDir, "testuser", ".ssh")
	if err := os.Chmod(sshDir, 0500); err != nil {
		t.Fatalf("Chmod %s: %v", sshDir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(sshDir, 0700) })
}

// A rewrite that fails must change nothing at all. Both of these paths remove entries
// and write the survivors, and both are reached from the broker's reconciliation; if
// either removed first and wrote second, this is where the account would be left
// holding a key list that authorizes nobody.
func TestAFailedRewriteLeavesTheWholeKeyListInPlace(t *testing.T) {
	t.Run("reconcile removal", func(t *testing.T) {
		baseDir := t.TempDir()
		akm := newTestManager(t, baseDir)
		before := plantedKeyList(t, baseDir)
		makeUnwritable(t, baseDir)

		removed, err := akm.RemoveOIDCKeys("testuser")
		if err == nil {
			t.Fatal("RemoveOIDCKeys reported success although the replacement could not be written")
		}
		if removed != 0 {
			t.Errorf("RemoveOIDCKeys reported %d entries removed after a failed write; the broker "+
				"would audit a revocation that did not happen", removed)
		}
		if after := readKeys(t, baseDir, "testuser"); after != before {
			t.Errorf("the key list changed despite the failed write:\n before %q\n after  %q", before, after)
		}
	})

	t.Run("expiry sweep", func(t *testing.T) {
		baseDir := t.TempDir()
		akm := newTestManager(t, baseDir)
		akm.SetKeyLifetime(time.Minute) // the planted broker entry is an hour old, so it is stale
		before := plantedKeyList(t, baseDir)
		makeUnwritable(t, baseDir)

		if err := akm.RemoveExpiredKeys("testuser"); err == nil {
			t.Fatal("RemoveExpiredKeys reported success although the replacement could not be written")
		}
		if after := readKeys(t, baseDir, "testuser"); after != before {
			t.Errorf("the key list changed despite the failed write:\n before %q\n after  %q", before, after)
		}
	})

	t.Run("install", func(t *testing.T) {
		baseDir := t.TempDir()
		akm := newTestManager(t, baseDir)
		before := plantedKeyList(t, baseDir)
		makeUnwritable(t, baseDir)

		err := akm.AddPublicKey("testuser", brokerKeyLine(time.Now(), "NEWKEY"), testExpiry())
		if err == nil {
			t.Fatal("AddPublicKey reported success although nothing could be written, so the broker " +
				"would hand out a session whose key is not in the file")
		}
		// The user's own key is the one that matters here: an install that dropped the
		// previous set before writing the new one would have taken it with it.
		if after := readKeys(t, baseDir, "testuser"); after != before {
			t.Errorf("the key list changed despite the failed write:\n before %q\n after  %q", before, after)
		}
	})
}

// A successful install must produce the complete set in one step: the new entry
// present, the superseded broker entry gone, and the user's own key untouched. This is
// the "compute the desired content and replace" shape stated positively — a file that
// ever held only some of these is a file some login was refused against.
func TestAnInstallPublishesTheCompleteDesiredSetAtOnce(t *testing.T) {
	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)
	plantedKeyList(t, baseDir)

	if err := akm.AddPublicKey("testuser", brokerKeyLine(time.Now(), "NEWKEY"), testExpiry()); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	after := readKeys(t, baseDir, "testuser")
	if !strings.Contains(after, "OWNKEY") {
		t.Errorf("the user's own key did not survive the install; file is %q", after)
	}
	if !strings.Contains(after, "NEWKEY") {
		t.Errorf("the key just installed is not in the file, so the login it authorized cannot be "+
			"used; file is %q", after)
	}
	if strings.Contains(after, "BROKERKEY") {
		t.Errorf("the superseded broker key is still authorized; file is %q", after)
	}
	if got := strings.Count(after, "# Added by OIDC PAM on"); got != 1 {
		t.Errorf("the file carries %d broker comments, not 1; file is %q", got, after)
	}
}
