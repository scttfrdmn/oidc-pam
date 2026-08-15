package main

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The shipped unit is part of the product: a host built by installing it is the
// host every deployment guide describes. Two of its settings decide whether SSH key
// provisioning can work at all, and both were wrong (#171) — so they are pinned
// here rather than left to be rediscovered on someone's cluster.
//
// No build tag: this reads a file and needs no cgo, so it runs everywhere the suite
// does.
func TestShippedUnitLetsTheBrokerWriteWhereItMust(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "systemd", "oidc-auth-broker.service")
	content, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	settings := unitSettings(string(content))

	// ProtectHome=true replaces /home with an empty tmpfs for the service. The
	// broker's whole job on a successful login is to write into the account's
	// ~/.ssh/authorized_keys, so under that setting every provisioning attempt fails
	// and no login can use SSH — while the unit looks well hardened.
	if home := settings["ProtectHome"]; home != "false" {
		t.Errorf("ProtectHome=%q: the broker cannot see /home, so it cannot install any "+
			"login's SSH key (#171)", home)
	}

	// ProtectSystem=strict makes the entire hierarchy read-only, so anything the
	// broker writes has to be named. Missing /home is the same outage as
	// ProtectHome=true; missing the state directory loses the issued keys and the
	// locks that serialize authorized_keys writes.
	readWrite := settings["ReadWritePaths"]
	for _, required := range []string{"/home", "/var/lib/oidc-pam"} {
		if !hasPath(readWrite, required) {
			t.Errorf("ReadWritePaths=%q does not include %s, which ProtectSystem=strict then "+
				"makes read-only to the broker", readWrite, required)
		}
	}

	// /home must be listed as optional. systemd fails the unit's namespace setup
	// when a ReadWritePaths entry does not exist, and the host whose homes are on
	// /export/home — the one the comment above ReadWritePaths tells to add its own
	// path — is exactly the host with no /home at all. Without the prefix, that host
	// gets a broker that will not start, which is worse than the outage being fixed.
	if !hasOptionalPath(readWrite, "/home") {
		t.Errorf("ReadWritePaths=%q lists /home without the \"-\" prefix, so systemd fails "+
			"the unit on a host that keeps homes elsewhere and has no /home", readWrite)
	}

	// The state directory has to exist before the first start; systemd creating it
	// is one less step an operator can miss.
	if got := settings["StateDirectory"]; got != "oidc-pam" {
		t.Errorf("StateDirectory=%q, want oidc-pam so /var/lib/oidc-pam exists on first start", got)
	}
	if got := settings["StateDirectoryMode"]; got != "0700" {
		t.Errorf("StateDirectoryMode=%q, want 0700: the directory holds the private half of "+
			"every issued key", got)
	}

	// CapabilityBoundingSet caps the effective set even for User=root, so a capability
	// missing from this list is one the broker does not have. Handing a newly written
	// authorized_keys to its owner needs CAP_CHOWN; without it every chown(2) to
	// another uid returns EPERM, provisioning fails, and every login through
	// configs/pam/ssh is denied (#202).
	//
	// This assertion exists because nothing else could catch it: the e2e harness runs
	// in a container with Docker's default capability set, which includes CAP_CHOWN,
	// so it is strictly more permissive than the host this unit describes.
	caps := strings.Fields(settings["CapabilityBoundingSet"])
	if !slices.Contains(caps, "CAP_CHOWN") {
		t.Errorf("CapabilityBoundingSet=%q omits CAP_CHOWN, so the broker cannot give an "+
			"account its own authorized_keys and every SSH login is denied (#202)",
			settings["CapabilityBoundingSet"])
	}

	// The hardening that is not in the way stays on, so this test cannot be
	// satisfied by simply removing the sandbox.
	for setting, want := range map[string]string{
		"ProtectSystem":   "strict",
		"NoNewPrivileges": "true",
		"PrivateTmp":      "true",
	} {
		if got := settings[setting]; got != want {
			t.Errorf("%s=%q, want %q", setting, got, want)
		}
	}
}

// The socket directory has to exist before ExecStart, on every boot.
//
// It holds the socket every PAM login connects to, and nothing but systemd can
// create it in time: /run is a tmpfs, so a directory the installer made is gone
// after a reboot, and ProtectSystem=strict makes /run read-only to the service, so
// the broker cannot create it either. It was listed in ReadWritePaths without a "-"
// prefix, which meant systemd failed the unit's namespace setup with 226/NAMESPACE
// before ExecStart ran, and Restart=always retried that forever. On a host wired
// with configs/pam/ssh, that is "nobody can SSH in after a reboot" (#211).
//
// Not verifiable from Go, and not verifiable on the machine most of this is written
// on: it needs systemd. This test pins the settings; `systemd-analyze verify` and a
// VM or nspawn boot with an empty /run are what confirm the behaviour.
func TestShippedUnitCreatesItsRuntimeDirectoryOnEveryBoot(t *testing.T) {
	settings := shippedUnitSettings(t)

	// oidc-auth, not oidc-pam: this must be the directory in server.socket_path,
	// /var/run/oidc-auth/broker.sock, which resolves to /run/oidc-auth.
	if got := settings["RuntimeDirectory"]; got != "oidc-auth" {
		t.Errorf("RuntimeDirectory=%q, want oidc-auth: without it /run/oidc-auth does not "+
			"exist after a reboot, and neither systemd nor the broker creates it, so the "+
			"broker never starts and no login succeeds (#211)", got)
	}

	// 0750 root:root is also what keeps the socket un-hijackable: write access to
	// this directory is enough to unlink the socket and bind an impostor, and
	// RuntimeDirectoryMode is reasserted on every start, so it heals a host whose
	// installer chowned the directory to an unprivileged account (#200).
	if got := settings["RuntimeDirectoryMode"]; got != "0750" {
		t.Errorf("RuntimeDirectoryMode=%q, want 0750: any account that can write to the "+
			"socket's directory can replace the socket with its own (#200)", got)
	}

	// And nothing under the /run tmpfs may be a bare ReadWritePaths entry, which is
	// the shape of the original bug: a hard dependency on a path that does not
	// survive a reboot and that nothing recreates.
	for _, entry := range strings.Fields(settings["ReadWritePaths"]) {
		if strings.HasPrefix(entry, "/run/") || strings.HasPrefix(entry, "/var/run/") {
			t.Errorf("ReadWritePaths lists %s: /run is a tmpfs, so on the first boot after "+
				"install systemd fails the unit's namespace setup before ExecStart. Have "+
				"systemd create the directory with RuntimeDirectory= instead (#211)", entry)
		}
	}
}

// The unit must not advertise a reload the broker cannot perform.
//
// It used to carry ExecReload=/bin/kill -HUP $MAINPID while the broker installed no
// SIGHUP handler, and Go's default disposition for SIGHUP is to terminate. So
// `systemctl reload oidc-auth-broker` — the action the unit itself advertises — and
// any logrotate postrotate stanza that reloads the service killed the broker, for a
// ten-second authentication outage that looked like a clean exit in the journal
// (#224).
//
// The broker now ignores SIGHUP (see ignoreSIGHUP, pinned by
// TestSIGHUPDoesNotKillTheBroker), so restoring this line would no longer kill it —
// it would silently do nothing while systemctl reported success, which is why the
// line stays out until there is a real reload to advertise.
func TestShippedUnitDoesNotAdvertiseAReloadTheBrokerCannotDo(t *testing.T) {
	settings := shippedUnitSettings(t)

	if got := settings["ExecReload"]; got != "" {
		t.Errorf("ExecReload=%q, want no ExecReload at all: the broker reads its "+
			"configuration once at startup and has no reload, so a reload either kills it "+
			"(SIGHUP's default disposition) or silently does nothing. Without ExecReload, "+
			"systemctl reload refuses the job and says so (#224)", got)
	}
}

// The broker is a long-lived root process on a host whose logins all depend on it,
// and it has no ceiling of its own. Without MemoryMax, a broker allocating without
// bound is the *host's* problem: the kernel's OOM killer picks a victim across every
// cgroup, and on a login host the thing it kills may be the reason anyone is logged
// in. With it, the same runaway is one service being restarted (#223).
//
// The value is not asserted — that is tuning, and an operator may have measured a
// need. What is asserted is that a ceiling exists and is finite, and that MemoryHigh
// sits below MemoryMax so reclaim is tried before anything is killed.
func TestShippedUnitPutsACeilingOnTheBrokersMemory(t *testing.T) {
	settings := shippedUnitSettings(t)

	max, ok := parseMemoryBytes(settings["MemoryMax"])
	if !ok {
		t.Fatalf("MemoryMax=%q: the shipped unit must put a finite ceiling on the broker's "+
			"memory, or a runaway broker takes the whole host's OOM killer with it (#223)",
			settings["MemoryMax"])
	}

	high, ok := parseMemoryBytes(settings["MemoryHigh"])
	if !ok {
		t.Errorf("MemoryHigh=%q: without it the first thing that happens at the ceiling is a "+
			"kill, with no reclaim attempted and nothing in the journal leading up to it",
			settings["MemoryHigh"])
	} else if high >= max {
		t.Errorf("MemoryHigh=%q is not below MemoryMax=%q, so the throttle never engages "+
			"before the kill and serves no purpose", settings["MemoryHigh"], settings["MemoryMax"])
	}
}

// parseMemoryBytes reads a systemd memory value. Reports false for the values that
// mean "no limit" — "infinity", a bare percentage (which is relative to physical
// memory and so is not a ceiling this test can compare), and anything unparseable.
func parseMemoryBytes(value string) (int64, bool) {
	if value == "" || value == "infinity" || strings.HasSuffix(value, "%") {
		return 0, false
	}

	multipliers := []struct {
		suffix string
		scale  int64
	}{
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"T", 1 << 40},
	}
	digits, scale := value, int64(1)
	for _, m := range multipliers {
		// systemd accepts K/M/G/T and the KB/MB/… spellings, all base 1024.
		for _, suffix := range []string{m.suffix, m.suffix + "B"} {
			if strings.HasSuffix(value, suffix) {
				digits, scale = strings.TrimSuffix(value, suffix), m.scale
			}
		}
	}

	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n * scale, true
}

// The unit in DEPLOYMENT.md must not drift from the one this repo installs.
//
// An operator who follows the deployment guide types that unit in by hand rather
// than installing the shipped file — it is presented as the unit to use — so a
// setting the guide omits is a setting their host does not have. It had already
// drifted: the guide's copy carried neither CAP_CHOWN nor RuntimeDirectory=, so a
// host built from the guide had #202 (every SSH key provisioning denied by EPERM)
// and #211 (the broker never starts after a reboot) with both fixed in the shipped
// unit and the tests above passing.
//
// Only the settings whose absence is an outage are compared. The guide is allowed
// to differ in wording, ordering and commentary, and to omit tuning like
// LimitNOFILE — this is a check on what breaks, not a diff.
func TestTheDocumentedUnitAgreesWithTheShippedOne(t *testing.T) {
	shipped := shippedUnitSettings(t)

	path := filepath.Join("..", "..", "DEPLOYMENT.md")
	content, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	documented := unitSettings(string(content))
	if documented["ExecStart"] == "" {
		t.Fatalf("no systemd unit found in %s; this test is pinned to the unit the "+
			"deployment guide tells operators to write", path)
	}

	for _, setting := range []string{
		"ProtectHome",           // #171: an empty /home means no key can be installed
		"StateDirectory",        // the issued keys and the per-user locks
		"StateDirectoryMode",    //
		"RuntimeDirectory",      // #211: no socket directory after a reboot
		"RuntimeDirectoryMode",  // #200: and nobody else may write into it
		"CapabilityBoundingSet", // #202: CAP_CHOWN or every provisioning fails
		"ProtectSystem",         // the hardening that must not quietly come off
		"NoNewPrivileges",
		"MemoryMax",  // #223: a runaway broker must not be the host's OOM problem
		"MemoryHigh", //
	} {
		if documented[setting] != shipped[setting] {
			t.Errorf("DEPLOYMENT.md has %s=%q where the shipped unit has %q. An operator who "+
				"follows the guide gets the guide's value, so a fix that lands only in "+
				"configs/systemd/ has not shipped",
				setting, documented[setting], shipped[setting])
		}
	}

	// Neither unit may hard-depend on a path under the /run tmpfs — the shape of
	// #211, and the reason RuntimeDirectory= exists.
	for _, entry := range strings.Fields(documented["ReadWritePaths"]) {
		if strings.HasPrefix(entry, "/run/") || strings.HasPrefix(entry, "/var/run/") {
			t.Errorf("the unit in DEPLOYMENT.md lists %s in ReadWritePaths: /run is a tmpfs, "+
				"so systemd fails the unit's namespace setup on the first boot after install "+
				"(#211)", entry)
		}
	}
}

// shippedUnitSettings parses the unit this repo installs.
func shippedUnitSettings(t *testing.T) map[string]string {
	t.Helper()

	path := filepath.Join("..", "..", "configs", "systemd", "oidc-auth-broker.service")
	content, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return unitSettings(string(content))
}

// unitSettings collects the last value of each key in a systemd unit, ignoring
// comments. Last wins, as systemd does for non-list settings.
func unitSettings(content string) map[string]string {
	settings := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") ||
			strings.HasPrefix(line, "[") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		settings[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return settings
}

// hasPath reports whether a space-separated systemd path list contains path
// exactly, so that /var/lib/oidc-pam-other does not satisfy /var/lib/oidc-pam.
func hasPath(list, path string) bool {
	for _, field := range strings.Fields(list) {
		if strings.TrimPrefix(field, "-") == path {
			return true
		}
	}
	return false
}

// hasOptionalPath reports whether the list contains path with systemd's "-"
// prefix, which makes a path that does not exist non-fatal instead of a
// unit-starting failure.
func hasOptionalPath(list, path string) bool {
	return slices.Contains(strings.Fields(list), "-"+path)
}
