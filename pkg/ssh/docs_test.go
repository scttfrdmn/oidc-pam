package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	// The DST tests below name real zones, so the test binary carries the tz database
	// rather than depending on one being installed wherever the suite runs.
	_ "time/tzdata"
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
	// Local digits, not UTC ones: sshd resolves an unsuffixed timespec through
	// mktime(3) in the host's own zone, so UTC digits would move the expiry by the
	// host's offset. Which local offset it uses is the subject of
	// TestTheExpiryIsWrittenAtStandardTimeBecauseThatIsHowSSHDReadsIt — it is the
	// zone's *standard* offset whatever the time of year, so the expected value here is
	// derived that way rather than from expiresAt.Local(), which would make this test
	// pass or fail according to the date it happens to use and the zone the host is in.
	stdOffset := standardOffsetForTest(t, time.Local, expiresAt.Year())
	want := expiresAt.In(time.FixedZone("", stdOffset)).Format("20060102150405")
	if got := timespec; got != want {
		t.Errorf("the expiry is written as %q, want %q: sshd reads an unsuffixed timespec in "+
			"the host's own time zone at its standard offset, so writing UTC digits — or the "+
			"daylight-saving offset — would move the expiry", got, want)
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

// standardOffsetForTest derives a zone's standard-time offset without using the
// implementation under test: it takes the offset in force on 1 January and on 1 July
// and returns the smaller, which is standard time in any zone whose DST rule advances
// the clock. (Europe/Dublin, which the tz database encodes as permanent summer time
// with *negative* DST in winter, is the exception, and is not used below.)
func standardOffsetForTest(t *testing.T, loc *time.Location, year int) int {
	t.Helper()

	_, january := time.Date(year, 1, 1, 12, 0, 0, 0, loc).Zone()
	_, july := time.Date(year, 7, 1, 12, 0, 0, 0, loc).Zone()
	if january < july {
		return january
	}
	return july
}

// (#226) sshd resolves an unsuffixed timespec at the zone's *standard* offset, whatever
// the time of year, so that is the offset the option has to be written at.
//
// parse_absolute_time() in misc.c does memset(&tm, 0, sizeof(tm)), strptime(), then
// mktime(). The memset leaves tm_isdst == 0 and strptime does not set it; zero means
// "daylight saving is not in effect", not "work it out" (which is -1). Measured on both
// libcs that matter, for the wall clock 2026-08-14 12:00:00 in America/New_York:
//
//	tm_isdst =  0  ->  17:00 UTC  (12:00 EST)
//	tm_isdst = -1  ->  16:00 UTC  (12:00 EDT)
//
// identical on Darwin libc and on glibc 2.41. Rendering the expiry at the offset in
// force at that instant — what this used to do — therefore told sshd a time one hour
// later than intended for the whole DST half of the year: the broker ended the session
// and the audit trail said the access had ended, while the key still authenticated for
// another hour. The sweep read it back the same wrong way, so nothing noticed.
//
// The check below is what sshd will make of the digits, computed independently: parse
// them as a wall clock and subtract the zone's standard offset.
func TestTheExpiryIsWrittenAtStandardTimeBecauseThatIsHowSSHDReadsIt(t *testing.T) {
	for _, zone := range []string{
		"UTC",
		"America/New_York", // northern DST
		"Europe/Berlin",    // northern DST, positive offset
		"Australia/Sydney", // southern DST, so its summer is the other half of the year
		"Asia/Kolkata",     // a half-hour offset and no DST at all
		"Africa/Nairobi",   // no DST
	} {
		loc, err := time.LoadLocation(zone)
		if err != nil {
			t.Fatalf("LoadLocation(%q): %v", zone, err)
		}
		for _, when := range []time.Time{
			time.Date(2026, 1, 15, 9, 30, 0, 0, time.UTC),
			time.Date(2026, 8, 14, 16, 0, 0, 0, time.UTC),
			time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
		} {
			name := zone + "/" + when.Format("2006-01")
			t.Run(name, func(t *testing.T) {
				spec := formatExpiryTimespecIn(when, loc)

				// What sshd does with it: strptime into a zeroed tm, then mktime with
				// tm_isdst == 0, i.e. resolve the wall clock at the standard offset.
				nominal, err := time.ParseInLocation("20060102150405", spec, time.UTC)
				if err != nil {
					t.Fatalf("sshd could not parse %q: %v", spec, err)
				}
				std := standardOffsetForTest(t, loc, when.In(loc).Year())
				asSSHDReadsIt := nominal.Add(-time.Duration(std) * time.Second)
				if !asSSHDReadsIt.Equal(when) {
					t.Errorf("expiry %s written as %q, which sshd resolves to %s: %s out. "+
						"An expiry sshd reads as later than the session it belongs to is a key "+
						"that keeps working after the access ended",
						when, spec, asSSHDReadsIt, asSSHDReadsIt.Sub(when))
				}

				// And the sweep must read back what was written, or it removes a key
				// before or after sshd stops honouring it.
				back, ok := parseExpiryTimespecIn(spec, loc)
				if !ok {
					t.Fatalf("this package cannot read back the %q it wrote", spec)
				}
				if !back.Equal(when) {
					t.Errorf("%q reads back as %s, want %s: the sweep and sshd disagree about "+
						"when the key stops working", spec, back, when)
				}
			})
		}
	}
}

// The concrete case, spelled out, because it is the one that was wrong and an
// off-by-one-hour is easy to reintroduce while every round-trip test still passes.
func TestASummerExpiryIsNotWrittenAtTheDaylightSavingOffset(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}

	// 16:00 UTC on 14 August 2026 is 12:00 EDT, and 11:00 EST.
	when := time.Date(2026, 8, 14, 16, 0, 0, 0, time.UTC)
	const wantEST = "20260814110000"
	const daylight = "20260814120000" // what rendering at the offset in force gives

	got := formatExpiryTimespecIn(when, loc)
	if got == daylight {
		t.Errorf("the expiry is written as %q, the wall clock in EDT. sshd resolves an "+
			"unsuffixed timespec with tm_isdst = 0, so it reads that as 12:00 EST = 17:00 UTC "+
			"and keeps honouring the key for an hour after the session ended", got)
	}
	if got != wantEST {
		t.Errorf("the expiry is written as %q, want %q (the same instant at the zone's "+
			"standard offset)", got, wantEST)
	}

	// The reading side has to make the same assumption, or the sweep removes a key
	// before sshd stops honouring it and drops the user mid-session. An entry that says
	// 20260814120000 means 12:00 EST — 17:00 UTC — to sshd, even though 14 August is in
	// EDT, and it has to mean that here too.
	asSSHDReadsIt, ok := parseExpiryTimespecIn(daylight, loc)
	if !ok {
		t.Fatalf("%q cannot be read back", daylight)
	}
	if want := time.Date(2026, 8, 14, 17, 0, 0, 0, time.UTC); !asSSHDReadsIt.Equal(want) {
		t.Errorf("%q reads as %s, want %s (both in UTC): mktime with tm_isdst = 0 resolves "+
			"that wall clock at the standard offset, so reading it as daylight time makes the "+
			"sweep revoke the key an hour before sshd does",
			daylight, asSSHDReadsIt.UTC(), want.UTC())
	}

	// The Z form is what #226 proposed instead. It is correct for sshd 9.1+ and refused
	// outright by everything older, which is most of the supported platforms — hence
	// TestTheExpiryTimespecIsTheFormEverySupportedSSHDParses. It must still be *read*,
	// though, both because an sshd 9.1+ host's own keys may carry it and because an
	// operator may have written one by hand.
	utc, ok := parseExpiryTimespecIn("20260814160000Z", loc)
	if !ok {
		t.Fatal("the Z-suffixed form sshd 9.1+ accepts cannot be read")
	}
	if !utc.Equal(when) {
		t.Errorf("the Z form read back as %s, want %s (both in UTC)", utc.UTC(), when.UTC())
	}
}
