package auth

import (
	"os"
	"strings"
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

// TestGeoRestrictionWithoutDatabaseIsRefusedAtStartup pins the fix for what this
// test used to accept. A geo_restriction with no geoip_database_path resolves every
// country to "", so the restriction matched nothing and denied every login it
// applied to — an operator who names allowed_countries and forgets the database
// locks out the host. The old test observed that outcome, logged it, and asserted
// nothing.
//
// A missing database is now a startup error (#212): the broker refuses to run a
// restriction it cannot evaluate, which the operator sees at install time instead
// of at the first login.
func TestGeoRestrictionWithoutDatabaseIsRefusedAtStartup(t *testing.T) {
	for _, tc := range []struct {
		name       string
		restrictor config.GeoRestriction
	}{
		{"allowed countries", config.GeoRestriction{Providers: []string{"all"}, AllowedCountries: []string{"US", "CA"}}},
		{"blocked countries", config.GeoRestriction{Providers: []string{"all"}, BlockedCountries: []string{"XX"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				Authentication: config.AuthenticationConfig{
					TimeBasedPolicies: config.TimeBasedPolicies{
						GeoRestrictions: []config.GeoRestriction{tc.restrictor},
					},
				},
			}

			pe, err := NewPolicyEngine(cfg)
			if err == nil {
				pe.Close()
				t.Fatal("NewPolicyEngine accepted a geo restriction with no GeoIP database; " +
					"every login it applies to would be denied for a country it cannot resolve (#212)")
			}
			if !strings.Contains(err.Error(), "geoip_database_path") {
				t.Errorf("startup error does not name the setting the operator has to add: %v", err)
			}
		})
	}
}

// TestGeoRestrictionNeedsAProviderScope covers the other half: a restriction with
// no providers list matched no provider, so it was inert. Silently applying to
// nothing is the failure mode this whole change is about.
func TestGeoRestrictionNeedsAProviderScope(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TimeBasedPolicies: config.TimeBasedPolicies{
				GeoRestrictions: []config.GeoRestriction{
					{AllowedCountries: []string{"US"}},
				},
			},
		},
	}

	pe, err := NewPolicyEngine(cfg)
	if err == nil {
		pe.Close()
		t.Fatal("NewPolicyEngine accepted a geo restriction with an empty providers list, " +
			"which applies to no provider and therefore restricts nothing (#212)")
	}
	if !strings.Contains(err.Error(), "providers") {
		t.Errorf("startup error does not name the empty providers list: %v", err)
	}
}

// TestPolicyEngineClose verifies that Close is idempotent and safe to call
// multiple times.
func TestPolicyEngineClose(t *testing.T) {
	pe := &PolicyEngine{}
	pe.Close() // nil geoipDB — must not panic
	pe.Close() // second call — must not panic
}
