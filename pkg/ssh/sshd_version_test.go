package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestMain fixes the sshd version the rest of this package's tests see.
//
// (#199) AddPublicKey now refuses to install a key when the local sshd is too old to
// honour the expiry-time= option it writes, and that refusal reaches every test that
// installs a key. Left to probe the host, the suite's result would depend on which
// OpenSSH the machine running it happens to have — green on a developer's laptop, red
// on an old build host, for a reason that has nothing to do with the code under test.
// So the default here is a host that is new enough, and the tests that are about the
// version decide their own answer with stubSSHDProbe.
func TestMain(m *testing.M) {
	sshdVersionProbe = func() sshdProbe {
		return sshdProbe{version: sshdVersion{major: 9, minor: 6}, known: true, path: "/usr/sbin/sshd (test stub)"}
	}
	os.Exit(m.Run())
}

// stubSSHDProbe makes the version probe answer with probe for the duration of one
// test, resetting the memoized answer on both sides so that no test inherits or
// leaves behind a cached version.
func stubSSHDProbe(t *testing.T, probe sshdProbe) {
	t.Helper()

	previous := sshdVersionProbe
	sshdVersionProbe = func() sshdProbe { return probe }
	resetSSHDVersionCache()
	t.Cleanup(func() {
		sshdVersionProbe = previous
		resetSSHDVersionCache()
	})
}

// knownSSHD is a probe result for a host whose sshd was read successfully.
func knownSSHD(major, minor int) sshdProbe {
	return sshdProbe{version: sshdVersion{major: major, minor: minor}, known: true, path: "/usr/sbin/sshd"}
}

// The number this file refuses on and the number the documentation promises must be
// the same number. docs_test.go holds DEPLOYMENT.md and README.md to
// minOpenSSHVersion; if the comparison here drifted from it, an operator would be
// told one prerequisite and refused by another.
func TestMinSSHDVersionIsTheDocumentedRequirement(t *testing.T) {
	if got := minSSHDVersion.String(); got != minOpenSSHVersion {
		t.Errorf("this package refuses below OpenSSH %s but documents %s as the minimum",
			got, minOpenSSHVersion)
	}
	if parsed, ok := parseSSHDVersionNumber(minOpenSSHVersion); !ok || parsed != minSSHDVersion {
		t.Errorf("minOpenSSHVersion %q does not parse to the version this file compares against (%v, ok=%t)",
			minOpenSSHVersion, parsed, ok)
	}
}

// The boundary is the whole decision: expiry-time= arrives in OpenSSH 7.7, so 7.6
// must be refused and 7.7 must be accepted.
//
// Both directions matter and they fail differently. Accepting 7.6 is the #199 defect:
// a key installed on a host that rejects the entry carrying it, so the login is
// reported as successful and SSH then answers Permission denied. Refusing 7.7 is an
// outage on a host that works perfectly well.
func TestTheExpiryOptionIsRefusedExactlyBelowOpenSSH77(t *testing.T) {
	for _, tc := range []struct {
		major, minor int
		refused      bool
	}{
		{6, 6, true},  // CentOS 6 era
		{7, 4, true},  // Amazon Linux 2, RHEL/CentOS 7 — the population #199 is about
		{7, 6, true},  // the last release without expiry-time=
		{7, 7, false}, // the release that added it
		{7, 8, false},
		{8, 2, false}, // where the option was mistakenly believed to have arrived
		{9, 6, false},
		{10, 0, false}, // two-digit major: newer than 7.7 by number, not by string
	} {
		name := fmt.Sprintf("%d.%d", tc.major, tc.minor)
		t.Run(name, func(t *testing.T) {
			stubSSHDProbe(t, knownSSHD(tc.major, tc.minor))

			err := sshdSupportsKeyExpiry()
			if tc.refused && err == nil {
				t.Fatalf("OpenSSH %s was accepted; it does not understand expiry-time=, so every key "+
					"installed on such a host is rejected by sshd and the login it authorized cannot "+
					"be used", name)
			}
			if !tc.refused && err != nil {
				t.Fatalf("OpenSSH %s was refused, denying every login on a host that honours the "+
					"option: %v", name, err)
			}
			if !tc.refused {
				return
			}

			// The message is the only thing an operator gets. It has to name what was found,
			// what is needed, and what to do about it.
			message := err.Error()
			for _, want := range []string{name, minOpenSSHVersion, "/usr/sbin/sshd", "Permission denied", "Upgrade"} {
				if !strings.Contains(message, want) {
					t.Errorf("the refusal never mentions %q, so it does not tell the operator what to "+
						"do: %q", want, message)
				}
			}
		})
	}
}

// The refusal has to happen before anything is written. A broker that installs the
// key and then reports failure has left a credential behind; a broker that installs
// the key and reports success is the #199 defect itself.
func TestAddPublicKeyRefusesToInstallAKeyTheLocalSSHDWouldReject(t *testing.T) {
	stubSSHDProbe(t, knownSSHD(7, 6))

	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	err := akm.AddPublicKey("testuser", brokerKeyLine(time.Now(), "TOOOLD"), testExpiry())
	if err == nil {
		t.Fatal("AddPublicKey installed a key on an sshd that refuses the entry carrying it, and " +
			"reported success: the login is authorized and cannot be used")
	}
	if !strings.Contains(err.Error(), "7.6") || !strings.Contains(err.Error(), minOpenSSHVersion) {
		t.Errorf("the refusal does not name the version found and the version needed: %v", err)
	}

	// Nothing may be left behind — not the file, and not the .ssh directory the write
	// would have created on its way there.
	authorizedKeys := filepath.Join(baseDir, "testuser", ".ssh", "authorized_keys")
	if _, statErr := os.Lstat(authorizedKeys); statErr == nil {
		t.Errorf("a key list was written at %s despite the refusal: %q", authorizedKeys,
			readKeys(t, baseDir, "testuser"))
	}
}

// 7.7 is the release that added the option, so 7.7 must provision normally — and the
// entry it writes must still carry the expiry, because that is the thing the version
// requirement exists to protect.
func TestAddPublicKeyInstallsOnTheOldestSSHDThatUnderstandsTheOption(t *testing.T) {
	stubSSHDProbe(t, knownSSHD(7, 7))

	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	expiresAt := testExpiry()
	if err := akm.AddPublicKey("testuser", brokerKeyLine(time.Now(), "SEVENSEVEN"), expiresAt); err != nil {
		t.Fatalf("AddPublicKey refused OpenSSH 7.7, which is the version that added expiry-time=: %v", err)
	}
	content := readKeys(t, baseDir, "testuser")
	if !strings.Contains(content, expiryTimeOption+"=") {
		t.Errorf("the installed entry carries no %s= option, so nothing but the broker's memory "+
			"expires the key; file is %q", expiryTimeOption, content)
	}
}

// An undetermined version is allowed through, deliberately (see sshdSupportsKeyExpiry).
// The probe reads a binary that need not be the sshd the session arrives through, so a
// refusal must rest on positive evidence: turning "the broker could not run a
// subprocess" into "nobody can log in to this host" would be an outage the operator
// cannot switch off.
func TestAnUndeterminedSSHDVersionDoesNotStopProvisioning(t *testing.T) {
	stubSSHDProbe(t, sshdProbe{why: "no sshd binary at /usr/sbin/sshd"})

	baseDir := t.TempDir()
	akm := newTestManager(t, baseDir)

	if err := akm.AddPublicKey("testuser", brokerKeyLine(time.Now(), "UNKNOWN"), testExpiry()); err != nil {
		t.Fatalf("provisioning was refused because the sshd version could not be read, which denies "+
			"every login on any host where the probe cannot see the binary: %v", err)
	}
}

// The banners are the real thing: what these builds actually print. A parser that
// only handles the tidy form is a parser that reports every real host as
// undetermined, which would quietly disable the check.
func TestParseSSHDVersionBanner(t *testing.T) {
	for name, tc := range map[string]struct {
		banner string
		want   sshdVersion
		ok     bool
	}{
		"rhel7 sshd usage, banner on the second line": {
			banner: "sshd: illegal option -- V\nOpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017\n" +
				"usage: sshd [-46DdeiqTt] [-C connection_spec] [-c host_cert_file]\n",
			want: sshdVersion{7, 4}, ok: true,
		},
		"ubuntu 24.04, vendor addendum": {
			banner: "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024\n",
			want:   sshdVersion{9, 6}, ok: true,
		},
		"no portable suffix": {
			banner: "OpenSSH_7.7, OpenSSL 1.0.2o  27 Mar 2018\n",
			want:   sshdVersion{7, 7}, ok: true,
		},
		"two-digit major": {
			banner: "OpenSSH_10.0p2, OpenSSL 3.5.0 8 Apr 2025\n",
			want:   sshdVersion{10, 0}, ok: true,
		},
		"hpn patched": {
			banner: "OpenSSH_7.4p1-hpn14v7, OpenSSL 1.0.2k-fips\n",
			want:   sshdVersion{7, 4}, ok: true,
		},
		"another program entirely": {
			banner: "Dropbear v2020.81\n",
			ok:     false,
		},
		"the name without a version": {
			banner: "OpenSSH_for_Windows_8.1p1\n",
			ok:     false,
		},
		"nothing at all": {
			banner: "",
			ok:     false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := parseSSHDVersionBanner(tc.banner)
			if ok != tc.ok {
				t.Fatalf("parseSSHDVersionBanner(%q) ok=%t, want %t (got %v)", tc.banner, ok, tc.ok, got)
			}
			if ok && got != tc.want {
				t.Errorf("parseSSHDVersionBanner(%q) = %v, want %v", tc.banner, got, tc.want)
			}
		})
	}
}

// pointSSHDSearchAtScript installs a shell script as the only sshd the probe will
// find, so that the real exec path — arguments, environment, both output streams and
// the exit status — is exercised without an sshd on the machine running the tests.
//
// It also puts the real probe back in place of TestMain's stub, so that a test using
// it exercises the whole decision and not just the parser.
func pointSSHDSearchAtScript(t *testing.T, script string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "sshd")
	if err := os.WriteFile(path, []byte(script), 0700); err != nil { // #nosec G306 -- test fixture
		t.Fatalf("WriteFile %s: %v", path, err)
	}
	previousPaths := sshdSearchPaths
	previousProbe := sshdVersionProbe
	sshdSearchPaths = []string{path}
	sshdVersionProbe = probeLocalSSHD
	resetSSHDVersionCache()
	t.Cleanup(func() {
		sshdSearchPaths = previousPaths
		sshdVersionProbe = previousProbe
		resetSSHDVersionCache()
	})
	return path
}

// The version of the sshd builds this check exists for arrives on *stderr*, from
// sshd's usage output, with a non-zero exit status: those builds have no -V option at
// all. A probe that read stdout, or that trusted the exit status, would report every
// one of them as undetermined and never refuse anything.
func TestTheProbeReadsTheBannerAnOldSSHDPrintsWhenItRefusesMinusV(t *testing.T) {
	pointSSHDSearchAtScript(t, "#!/bin/sh\n"+
		"echo 'sshd: illegal option -- V' >&2\n"+
		"echo 'OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017' >&2\n"+
		"echo 'usage: sshd [-46DdeiqTt] [-C connection_spec]' >&2\n"+
		"exit 1\n")

	probe := probeLocalSSHD()
	if !probe.known {
		t.Fatalf("the probe could not read a version an old sshd printed on stderr: %s", probe.why)
	}
	if probe.version != (sshdVersion{7, 4}) {
		t.Fatalf("probe read OpenSSH %s, want 7.4", probe.version)
	}
	if err := sshdSupportsKeyExpiry(); err == nil {
		// Guard against the probe working and the decision not being taken from it.
		t.Error("a 7.4 sshd read from the host was not refused")
	}
}

// A modern sshd prints the banner on -V and exits zero. Same parse, other stream.
func TestTheProbeReadsTheBannerAModernSSHDPrints(t *testing.T) {
	pointSSHDSearchAtScript(t, "#!/bin/sh\necho 'OpenSSH_9.6p1, OpenSSL 3.0.13 30 Jan 2024'\n")

	probe := probeLocalSSHD()
	if !probe.known || probe.version != (sshdVersion{9, 6}) {
		t.Fatalf("probe = %+v, want a known 9.6", probe)
	}
	if err := sshdSupportsKeyExpiry(); err != nil {
		t.Errorf("a 9.6 sshd was refused: %v", err)
	}
}

// When there is no sshd to read, the operator has to be told which paths were tried —
// that is the difference between "this host is too old" and "the broker looked in the
// wrong place", and the broker goes on provisioning either way.
func TestTheProbeNamesEveryPathItTriedWhenItFindsNoSSHD(t *testing.T) {
	previous := sshdSearchPaths
	sshdSearchPaths = []string{filepath.Join(t.TempDir(), "absent", "sshd")}
	t.Cleanup(func() { sshdSearchPaths = previous })

	probe := probeLocalSSHD()
	if probe.known {
		t.Fatalf("the probe claimed to know a version with no sshd present: %+v", probe)
	}
	if !strings.Contains(probe.why, sshdSearchPaths[0]) {
		t.Errorf("the probe does not say where it looked: %q", probe.why)
	}
}

// A binary that never answers must not hold the login open. The broker probes on the
// login path, so an unbounded wait here is a login that hangs until sshd's
// LoginGraceTime kills it — the same failure getentTimeout exists to prevent.
func TestTheProbeIsBoundedInTime(t *testing.T) {
	pointSSHDSearchAtScript(t, "#!/bin/sh\nsleep 30\n")

	previousTimeout := sshdProbeTimeout
	sshdProbeTimeout = 150 * time.Millisecond
	t.Cleanup(func() { sshdProbeTimeout = previousTimeout })

	started := time.Now()
	probe := probeLocalSSHD()
	elapsed := time.Since(started)

	if probe.known {
		t.Errorf("the probe returned a version from a binary that never printed one: %+v", probe)
	}
	if elapsed > 5*time.Second {
		t.Errorf("the probe took %s against a hanging binary; a login would have waited that long",
			elapsed)
	}
}

// The probe execs a subprocess, so it must not run once per authentication.
func TestTheProbeRunsOncePerProcess(t *testing.T) {
	var calls atomic.Int64
	previous := sshdVersionProbe
	sshdVersionProbe = func() sshdProbe {
		calls.Add(1)
		return knownSSHD(9, 6)
	}
	resetSSHDVersionCache()
	t.Cleanup(func() {
		sshdVersionProbe = previous
		resetSSHDVersionCache()
	})

	for i := 0; i < 5; i++ {
		if err := sshdSupportsKeyExpiry(); err != nil {
			t.Fatalf("sshdSupportsKeyExpiry: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("the sshd binary was exec'd %d times for 5 key installations, not once", got)
	}
}

// A version that cannot be ordered is not a version. atLeast is what the whole
// refusal turns on, and string comparison — the obvious wrong implementation — puts
// "10.0" before "7.7".
func TestSSHDVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		have, want sshdVersion
		atLeast    bool
	}{
		{sshdVersion{7, 7}, sshdVersion{7, 7}, true},
		{sshdVersion{7, 6}, sshdVersion{7, 7}, false},
		{sshdVersion{7, 10}, sshdVersion{7, 7}, true},
		{sshdVersion{6, 9}, sshdVersion{7, 7}, false},
		{sshdVersion{10, 0}, sshdVersion{7, 7}, true},
	} {
		if got := tc.have.atLeast(tc.want); got != tc.atLeast {
			t.Errorf("%v.atLeast(%v) = %t, want %t", tc.have, tc.want, got, tc.atLeast)
		}
	}
}

// The output of a program that is not sshd is bounded before it is read: the probe
// runs as root against a path that is only conventionally sshd, and a binary that
// prints without stopping must not be able to grow the broker's memory.
func TestTheProbeBoundsWhatItReads(t *testing.T) {
	out := &cappedBuffer{limit: 16}
	written, err := out.Write([]byte(strings.Repeat("x", 1<<20)))
	if err != nil || written != 1<<20 {
		t.Fatalf("Write returned (%d, %v); a short write would hand the subprocess an error for "+
			"output nobody wanted", written, err)
	}
	if len(out.String()) != 16 {
		t.Errorf("the probe buffered %d bytes with a 16-byte limit", len(out.String()))
	}
}
