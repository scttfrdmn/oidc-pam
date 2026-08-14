package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The entry this package installs carries an `expiry-time=` option, which is how
// sshd — rather than a broker that may not be running — stops honouring a stale key
// (#171). That option is not universally available: it arrived in OpenSSH
// minOpenSSHVersion, and an sshd that does not recognise an authorized_keys option
// refuses the entry carrying it. On an older host, therefore, every key this
// package writes is rejected, the file looks correct, and the account is
// authenticated and then told `Permission denied (publickey)`.
//
// That is a deployment requirement, and a requirement stated only in a Go comment
// is one an operator learns from a login that does not work. These tests read the
// operator-facing documents and hold them to the same version the code uses, so the
// two cannot drift apart.

// docsThatStateTheRequirement are the documents an operator reads before installing:
// the deployment guide's prerequisites, and the platform table in the README that
// says what is expected to work.
var docsThatStateTheRequirement = []string{
	filepath.Join("..", "..", "DEPLOYMENT.md"),
	filepath.Join("..", "..", "README.md"),
}

func TestTheDocsStateTheMinimumOpenSSHVersion(t *testing.T) {
	for _, doc := range docsThatStateTheRequirement {
		content := readDoc(t, doc)

		// The requirement phrasing, not merely the number: a document that mentions
		// 7.7 somewhere in passing has not told anyone it is a minimum.
		want := fmt.Sprintf("OpenSSH %s or newer", minOpenSSHVersion)
		if !strings.Contains(content, want) {
			t.Errorf("%s never says %q, so nothing tells an operator that a host with an "+
				"older sshd rejects every key the broker installs", filepath.Base(doc), want)
		}

		// The version alone is a number with no reason attached; an operator deciding
		// whether it applies to them needs to know it is the key option that requires
		// it, not the module or the broker.
		if !strings.Contains(content, expiryTimeOption) {
			t.Errorf("%s states no reason for the OpenSSH requirement: it does not mention "+
				"the %s= option the requirement comes from", filepath.Base(doc), expiryTimeOption)
		}
	}
}

// The requirement excludes platforms this project used to list as supported, and a
// platform table that says "expected to work" about a host where no key can be
// installed is worse than one that says nothing. Amazon Linux 2 and RHEL/CentOS 7
// both ship OpenSSH 7.4p1.
func TestTheDocsNameThePlatformsThatAreTooOld(t *testing.T) {
	const tooOld = "7.4p1"

	for _, doc := range docsThatStateTheRequirement {
		content := readDoc(t, doc)
		if !strings.Contains(content, tooOld) {
			t.Errorf("%s does not name %s, the version Amazon Linux 2 and RHEL/CentOS 7 ship, "+
				"so a reader cannot tell those platforms are excluded", filepath.Base(doc), tooOld)
		}
		if !strings.Contains(content, "Amazon Linux 2") {
			t.Errorf("%s does not mention Amazon Linux 2, which cannot run this", filepath.Base(doc))
		}
	}
}

// A timespec suffixed with Z to mean UTC is OpenSSH 9.1 and newer. Every sshd before
// that parses a timespec by its length and rejects the 15-character form, refusing
// the entry with it — so writing UTC would restrict this to Debian 12-era hosts
// while satisfying every other test in this package, including the e2e suite, which
// runs on Debian 12. Hence a test about the shape of what is written.
func TestTheExpiryTimespecIsTheFormEverySupportedSSHDParses(t *testing.T) {
	// A fixed instant, so a host in any time zone gets a deterministic length and
	// a value that must equal the same instant rendered locally.
	expiresAt := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)

	timespec := formatExpiryTimespec(expiresAt)

	if strings.ContainsAny(timespec, "Zz") {
		t.Errorf("the expiry is written as %q: the Z suffix means UTC only from OpenSSH 9.1, "+
			"and every sshd before that rejects the entry carrying it", timespec)
	}
	if !regexp.MustCompile(`^\d{14}$`).MatchString(timespec) {
		t.Errorf("the expiry is written as %q, not the 14-digit YYYYMMDDHHMMSS sshd(8) "+
			"documents", timespec)
	}
	if got, want := timespec, expiresAt.Local().Format("20060102150405"); got != want {
		t.Errorf("the expiry is written as %q, want %q: sshd reads an unsuffixed timespec in "+
			"the host's own time zone, so writing UTC digits would move the expiry by the "+
			"host's offset", got, want)
	}

	// And what is written must be read back as the same instant, or the sweep and
	// sshd disagree about when the key stopped working.
	parsed, ok := parseExpiryTimespec(timespec)
	if !ok {
		t.Fatalf("the expiry this package writes, %q, cannot be read back", timespec)
	}
	if !parsed.Equal(expiresAt) {
		t.Errorf("%q reads back as %s, want %s", timespec, parsed, expiresAt)
	}
}

func readDoc(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
