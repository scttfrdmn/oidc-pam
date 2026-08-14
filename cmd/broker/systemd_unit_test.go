package main

import (
	"os"
	"path/filepath"
	"slices"
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
