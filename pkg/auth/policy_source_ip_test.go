package auth

import (
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// networkPolicyEngine builds an engine whose only opinion is the network
// requirement under test.
func networkPolicyEngine(t *testing.T, nr config.NetworkRequirements) *PolicyEngine {
	t.Helper()

	pe, err := NewPolicyEngine(&config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime:       time.Hour,
			NetworkRequirements: nr,
		},
	})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	t.Cleanup(pe.Close)
	return pe
}

func evaluate(t *testing.T, pe *PolicyEngine, req *AuthRequest) *PolicyResult {
	t.Helper()

	result, err := pe.EvaluateRequest(req)
	if err != nil {
		t.Fatalf("EvaluateRequest: %v", err)
	}
	return result
}

// The headline regression test for #169: require_private_network has to be able to
// tell a private source address from a public one.
//
// It could not, because no client ever sent source_ip and isPrivateIP("") is
// false, so the requirement refused every login on the host — including the ones
// it was configured to admit. This test was impossible to write against that
// defect: both cases were the empty string and both were denied.
func TestRequirePrivateNetworkDistinguishesPrivateFromPublic(t *testing.T) {
	pe := networkPolicyEngine(t, config.NetworkRequirements{
		RequirePrivateNetwork: true,
		UnknownSourceIP:       config.UnknownSourceIPDeny,
	})

	tests := []struct {
		name        string
		sourceIP    string
		wantAllowed bool
	}{
		{"RFC 1918 /8", "10.11.12.13", true},
		{"RFC 1918 /12", "172.16.4.5", true},
		{"RFC 1918 /16", "192.168.1.100", true},
		{"a public address", "203.0.113.7", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluate(t, pe, &AuthRequest{
				UserID:    "alice",
				SourceIP:  tt.sourceIP,
				LoginType: "ssh",
				Timestamp: time.Now(),
			})
			if result.Allowed != tt.wantAllowed {
				t.Errorf("require_private_network with source_ip %q: allowed = %v (%s), want %v",
					tt.sourceIP, result.Allowed, result.Reason, tt.wantAllowed)
			}
		})
	}
}

func TestRequireTailscaleDistinguishesTailscaleFromEverythingElse(t *testing.T) {
	pe := networkPolicyEngine(t, config.NetworkRequirements{
		RequireTailscale: true,
		UnknownSourceIP:  config.UnknownSourceIPDeny,
	})

	if result := evaluate(t, pe, &AuthRequest{UserID: "alice", SourceIP: "100.101.102.103"}); !result.Allowed {
		t.Errorf("a Tailscale address was refused: %s", result.Reason)
	}
	if result := evaluate(t, pe, &AuthRequest{UserID: "alice", SourceIP: "192.168.1.100"}); result.Allowed {
		t.Error("require_tailscale admitted an address outside 100.64.0.0/10")
	}
}

// An absent source_ip is "the broker does not know where this came from", which is
// a third answer and not the same as "a public network". Which way it falls is the
// operator's, stated in config: the zero value used to decide it, and it decided
// deny for every login including the console.
func TestUnknownSourceIPIsTheOperatorsDecision(t *testing.T) {
	t.Run("deny fails closed", func(t *testing.T) {
		pe := networkPolicyEngine(t, config.NetworkRequirements{
			RequirePrivateNetwork: true,
			UnknownSourceIP:       config.UnknownSourceIPDeny,
		})

		result := evaluate(t, pe, &AuthRequest{UserID: "alice", LoginType: "console"})
		if result.Allowed {
			t.Fatal("unknown_source_ip: deny admitted a login with no source_ip")
		}
		// The reason has to say the origin was unknown, not that it was public: it is
		// what the operator reads out of the audit trail, and it is the difference
		// between a misconfiguration and an attack.
		if want := "requires a known network origin"; !contains(result.Reason, want) {
			t.Errorf("reason = %q, want it to mention %q", result.Reason, want)
		}
	})

	t.Run("allow admits it and marks the waiver", func(t *testing.T) {
		pe := networkPolicyEngine(t, config.NetworkRequirements{
			RequirePrivateNetwork: true,
			UnknownSourceIP:       config.UnknownSourceIPAllow,
		})

		result := evaluate(t, pe, &AuthRequest{UserID: "alice", LoginType: "console"})
		if !result.Allowed {
			t.Fatalf("unknown_source_ip: allow refused a login with no source_ip: %s", result.Reason)
		}
		// Broker.Authenticate turns this into a network_requirement_waived audit
		// event. A requirement that was configured and then not applied must not be
		// invisible.
		if waived, ok := result.Metadata[MetadataSourceIPUnknown].(bool); !ok || !waived {
			t.Errorf("result.Metadata[%q] = %v, want true", MetadataSourceIPUnknown, result.Metadata[MetadataSourceIPUnknown])
		}
	})

	t.Run("allow does not admit a public address", func(t *testing.T) {
		pe := networkPolicyEngine(t, config.NetworkRequirements{
			RequirePrivateNetwork: true,
			UnknownSourceIP:       config.UnknownSourceIPAllow,
		})

		if result := evaluate(t, pe, &AuthRequest{UserID: "alice", SourceIP: "203.0.113.7"}); result.Allowed {
			t.Error("unknown_source_ip: allow waived the requirement for a login that did report an address")
		}
	})

	t.Run("no requirement, no opinion", func(t *testing.T) {
		pe := networkPolicyEngine(t, config.NetworkRequirements{})

		if result := evaluate(t, pe, &AuthRequest{UserID: "alice", LoginType: "console"}); !result.Allowed {
			t.Errorf("a login with no source_ip was refused with no network requirement configured: %s", result.Reason)
		}
	})
}

// The second half of #169's impact: every user scored 70 from their second login
// on. A first login recorded a location with an empty subnet and an empty country,
// which matches nothing — but its existence ended the "no history yet" exemption,
// so IsUnusual fell through to true for every login after it, forever.
func TestRepeatLoginFromTheSameSubnetIsNotUnusual(t *testing.T) {
	pe := networkPolicyEngine(t, config.NetworkRequirements{})

	const sourceIP = "192.168.1.100"
	pe.RecordLocation("alice", sourceIP)

	result := evaluate(t, pe, &AuthRequest{UserID: "alice", SourceIP: sourceIP, LoginType: "ssh"})
	for _, factor := range result.RiskFactors {
		if factor == "Unusual location" {
			t.Errorf("a second login from %s was scored as an unusual location; factors: %v",
				sourceIP, result.RiskFactors)
		}
	}

	// A different /24 still is unusual: the exemption above must not be a blanket one.
	elsewhere := evaluate(t, pe, &AuthRequest{UserID: "alice", SourceIP: "203.0.113.7", LoginType: "ssh"})
	if !containsString(elsewhere.RiskFactors, "Unusual location") {
		t.Errorf("a login from a subnet with no history was not scored as unusual; factors: %v",
			elsewhere.RiskFactors)
	}
}

// A login with no address cannot be recorded as a location, and recording it
// anyway is what turned the whole history into a permanent "unusual" verdict.
func TestALoginWithNoLocationIsNotRecorded(t *testing.T) {
	pe := networkPolicyEngine(t, config.NetworkRequirements{})

	pe.RecordLocation("alice", "")
	if n := pe.locationHistory.Len("alice"); n != 0 {
		t.Fatalf("recorded %d location(s) for a login with no source_ip, want 0", n)
	}

	// And the next real login is still that user's first, so it is not unusual.
	result := evaluate(t, pe, &AuthRequest{UserID: "alice", SourceIP: "192.168.1.100", LoginType: "ssh"})
	if containsString(result.RiskFactors, "Unusual location") {
		t.Errorf("the first locatable login was scored as unusual; factors: %v", result.RiskFactors)
	}
}

// An unknown origin is named as unknown rather than reported as a public network,
// because the risk factors are what an operator reads to find out why a login
// scored what it did.
func TestRiskFactorsNameAnUnknownOriginAsUnknown(t *testing.T) {
	pe := networkPolicyEngine(t, config.NetworkRequirements{})

	unknown := evaluate(t, pe, &AuthRequest{UserID: "alice", LoginType: "console"})
	if !containsString(unknown.RiskFactors, "Unknown network origin") {
		t.Errorf("factors for a login with no source_ip = %v, want one naming the unknown origin",
			unknown.RiskFactors)
	}
	if containsString(unknown.RiskFactors, "Public network access") {
		t.Errorf("a login with no source_ip was reported as public network access: %v", unknown.RiskFactors)
	}

	public := evaluate(t, pe, &AuthRequest{UserID: "alice", SourceIP: "203.0.113.7", LoginType: "ssh"})
	if !containsString(public.RiskFactors, "Public network access") {
		t.Errorf("factors for a public source_ip = %v, want one naming the public network", public.RiskFactors)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
