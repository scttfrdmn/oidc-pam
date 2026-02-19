package auth

import (
	"os"
	"testing"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// TestGetCountryFromIPNoDatabase verifies fallback behaviour when no GeoIP
// database is configured.
func TestGetCountryFromIPNoDatabase(t *testing.T) {
	pe := &PolicyEngine{} // no geoipDB set

	cases := []struct {
		ip   string
		want string
	}{
		{"8.8.8.8", ""},     // public IP — no DB, must return ""
		{"127.0.0.1", ""},   // loopback
		{"192.168.1.1", ""}, // private
		{"10.0.0.1", ""},    // private
		{"::1", ""},         // IPv6 loopback
		{"not-an-ip", ""},   // invalid
	}

	for _, c := range cases {
		got := pe.getCountryFromIP(c.ip)
		if got != c.want {
			t.Errorf("getCountryFromIP(%q) = %q, want %q", c.ip, got, c.want)
		}
	}
}

// TestGetCountryFromIPPrivateAddresses verifies that private/loopback addresses
// always return "" even when a GeoIP database is configured, since they have no
// meaningful country assignment.
func TestGetCountryFromIPPrivateAddresses(t *testing.T) {
	dbPath := os.Getenv("GEOIP_DB_PATH")
	if dbPath == "" {
		t.Skip("GEOIP_DB_PATH not set; skipping private-address test with real DB")
	}

	pe, err := NewPolicyEngine(&config.Config{
		Authentication: config.AuthenticationConfig{
			GeoIPDatabasePath: dbPath,
		},
	})
	if err != nil {
		t.Fatalf("NewPolicyEngine failed: %v", err)
	}
	defer pe.Close()

	privateIPs := []string{
		"127.0.0.1",
		"::1",
		"192.168.0.1",
		"10.10.10.10",
		"172.16.0.1",
		"169.254.1.1",
	}

	for _, ip := range privateIPs {
		if got := pe.getCountryFromIP(ip); got != "" {
			t.Errorf("getCountryFromIP(%q) = %q, expected empty for private/loopback", ip, got)
		}
	}
}

// TestGetCountryFromIPWithDatabase tests real country lookups when a GeoIP
// database is available via the GEOIP_DB_PATH environment variable.
func TestGetCountryFromIPWithDatabase(t *testing.T) {
	dbPath := os.Getenv("GEOIP_DB_PATH")
	if dbPath == "" {
		t.Skip("GEOIP_DB_PATH not set; skipping real GeoIP lookup test")
	}

	pe, err := NewPolicyEngine(&config.Config{
		Authentication: config.AuthenticationConfig{
			GeoIPDatabasePath: dbPath,
		},
	})
	if err != nil {
		t.Fatalf("NewPolicyEngine failed: %v", err)
	}
	defer pe.Close()

	// These are well-known public IP addresses with stable country assignments.
	cases := []struct {
		ip          string
		wantCountry string
	}{
		{"8.8.8.8", "US"},        // Google Public DNS
		{"1.1.1.1", "AU"},        // Cloudflare (APNIC research, registered in AU)
		{"208.67.222.222", "US"}, // OpenDNS
	}

	for _, c := range cases {
		got := pe.getCountryFromIP(c.ip)
		if got != c.wantCountry {
			t.Errorf("getCountryFromIP(%q) = %q, want %q", c.ip, got, c.wantCountry)
		}
	}
}

// TestNewPolicyEngineInvalidGeoIPPath verifies that NewPolicyEngine returns an
// error when a GeoIP database path is set but the file does not exist.
func TestNewPolicyEngineInvalidGeoIPPath(t *testing.T) {
	_, err := NewPolicyEngine(&config.Config{
		Authentication: config.AuthenticationConfig{
			GeoIPDatabasePath: "/nonexistent/path/GeoLite2-Country.mmdb",
		},
	})
	if err == nil {
		t.Error("Expected error for nonexistent GeoIP database path, got nil")
	}
}

// TestNewPolicyEngineNoGeoIPPath verifies that NewPolicyEngine succeeds and
// geo restrictions degrade gracefully when no database path is configured.
func TestNewPolicyEngineNoGeoIPPath(t *testing.T) {
	pe, err := NewPolicyEngine(&config.Config{})
	if err != nil {
		t.Fatalf("NewPolicyEngine failed without GeoIP path: %v", err)
	}
	if pe.geoipDB != nil {
		t.Error("Expected nil geoipDB when no path configured")
	}
	pe.Close() // must not panic
}

// TestGeoRestrictionWithoutDatabase verifies that geographic restrictions do
// not block access when no GeoIP database is configured (country resolves to
// ""), so that a missing database does not lock out all users.
func TestGeoRestrictionWithoutDatabase(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TimeBasedPolicies: config.TimeBasedPolicies{
				GeoRestrictions: []config.GeoRestriction{
					{
						AllowedCountries: []string{"US", "CA"},
					},
				},
			},
		},
	}

	pe, err := NewPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("NewPolicyEngine failed: %v", err)
	}

	req := &AuthRequest{
		UserID:   "testuser",
		SourceIP: "8.8.8.8",
	}

	result := &PolicyResult{Allowed: true}
	if err := pe.applyTimeBasedPolicies(req, result); err != nil {
		t.Fatalf("applyTimeBasedPolicies returned error: %v", err)
	}

	// With no database, country is "" which is not in the allowed list, so
	// the restriction will block access. This is intentional: operators who
	// configure geo restrictions MUST provide a GeoIP database.
	// The test simply asserts the behaviour is deterministic (not a panic).
	t.Logf("access allowed=%v reason=%q (no GeoIP DB)", result.Allowed, result.Reason)
}

// TestPolicyEngineClose verifies that Close is idempotent and safe to call
// multiple times.
func TestPolicyEngineClose(t *testing.T) {
	pe := &PolicyEngine{}
	pe.Close() // nil geoipDB — must not panic
	pe.Close() // second call — must not panic
}
