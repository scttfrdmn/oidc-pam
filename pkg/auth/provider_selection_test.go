package auth

import (
	"testing"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// selectionBroker builds a broker whose provider map holds exactly the given
// provider configs. The map is deliberately the only ordering input, so a
// selection that depends on Go's map iteration order shows up as a flake here.
func selectionBroker(providers ...config.OIDCProvider) *Broker {
	byName := make(map[string]*OIDCProvider, len(providers))
	for _, providerConfig := range providers {
		byName[providerConfig.Name] = &OIDCProvider{
			Name:   providerConfig.Name,
			Config: providerConfig,
		}
	}
	return &Broker{providers: byName}
}

func loginProvider(name string, priority int) config.OIDCProvider {
	return config.OIDCProvider{Name: name, Priority: priority, EnabledForLogin: true}
}

// Priority 1 is the most preferred, matching every shipped configuration: in
// configs/production/broker-enterprise.yaml the primary provider is priority 1
// and the one commented "Backup provider for failover" is priority 2.
func TestSelectProviderPrefersTheLowestPriorityNumber(t *testing.T) {
	broker := selectionBroker(
		loginProvider("contractors", 4),
		loginProvider("corporate-primary", 1),
		loginProvider("service-accounts", 3),
		loginProvider("corporate-backup", 2),
	)

	provider := broker.selectProvider()
	if provider == nil {
		t.Fatal("selectProvider returned nil with four eligible providers")
	}
	if provider.Name != "corporate-primary" {
		t.Errorf("selectProvider() = %s, want corporate-primary (priority 1)", provider.Name)
	}

	// The full order matters too: it is the failover order.
	want := []string{"corporate-primary", "corporate-backup", "service-accounts", "contractors"}
	assertOrder(t, broker, want)
}

// The bug: ranging over b.providers meant the selection could differ between
// two consecutive logins on the same host with the same config, sending users
// to a different identity provider at random.
func TestSelectProviderIsStableAcrossCalls(t *testing.T) {
	broker := selectionBroker(
		loginProvider("alpha", 5),
		loginProvider("bravo", 5),
		loginProvider("charlie", 5),
		loginProvider("delta", 5),
		loginProvider("echo", 5),
	)

	first := broker.selectProvider()
	if first == nil {
		t.Fatal("selectProvider returned nil")
	}
	// Equal priorities are broken by name, so this is deterministic rather than
	// merely repeatable-by-luck.
	if first.Name != "alpha" {
		t.Errorf("selectProvider() = %s, want alpha (first by name among equal priorities)", first.Name)
	}

	for i := 0; i < 100; i++ {
		if got := broker.selectProvider(); got.Name != first.Name {
			t.Fatalf("call %d selected %s, want %s on every call", i, got.Name, first.Name)
		}
	}
}

// A provider that omits `priority` must not outrank one that declares it:
// unset is 0, which would otherwise sort ahead of priority 1.
func TestSelectProviderTreatsUnsetPriorityAsLast(t *testing.T) {
	broker := selectionBroker(
		loginProvider("undeclared", 0),
		loginProvider("declared", 2),
	)

	if provider := broker.selectProvider(); provider.Name != "declared" {
		t.Errorf("selectProvider() = %s, want declared (priority 2 beats unset)", provider.Name)
	}
	assertOrder(t, broker, []string{"declared", "undeclared"})
}

// Negative priorities are not a documented way to mean "first"; they are a
// typo. Treat them like unset rather than letting one silently take over every
// login on the host.
func TestSelectProviderTreatsNegativePriorityAsUnset(t *testing.T) {
	broker := selectionBroker(
		loginProvider("typo", -1),
		loginProvider("declared", 3),
	)

	if provider := broker.selectProvider(); provider.Name != "declared" {
		t.Errorf("selectProvider() = %s, want declared", provider.Name)
	}
}

// With no priorities configured at all — the common single- and two-provider
// case — the order is still fixed, by name.
func TestSelectProviderWithNoPrioritiesOrdersByName(t *testing.T) {
	broker := selectionBroker(
		loginProvider("okta", 0),
		loginProvider("azure", 0),
		loginProvider("keycloak", 0),
	)

	assertOrder(t, broker, []string{"azure", "keycloak", "okta"})
}

func TestSelectProviderSkipsProvidersNotEnabledForLogin(t *testing.T) {
	broker := selectionBroker(
		config.OIDCProvider{Name: "disabled-but-preferred", Priority: 1},
		loginProvider("enabled", 9),
	)

	provider := broker.selectProvider()
	if provider == nil {
		t.Fatal("selectProvider returned nil with one eligible provider")
	}
	if provider.Name != "enabled" {
		t.Errorf("selectProvider() = %s, want enabled", provider.Name)
	}
}

// verification_only means "may confirm an identity, must not be logged in
// against". Set together with enabled_for_login it is contradictory config, and
// the safe reading is that it is not a login candidate.
func TestSelectProviderSkipsVerificationOnlyProviders(t *testing.T) {
	verificationOnly := loginProvider("orcid", 1)
	verificationOnly.VerificationOnly = true

	broker := selectionBroker(verificationOnly, loginProvider("globus", 2))

	provider := broker.selectProvider()
	if provider == nil {
		t.Fatal("selectProvider returned nil with one eligible provider")
	}
	if provider.Name != "globus" {
		t.Errorf("selectProvider() = %s, want globus (orcid is verification_only)", provider.Name)
	}
	assertOrder(t, broker, []string{"globus"})
}

func TestSelectProviderWithNoEligibleProviders(t *testing.T) {
	tests := map[string]*Broker{
		"no providers at all": selectionBroker(),
		"none enabled for login": selectionBroker(
			config.OIDCProvider{Name: "verify-only", Priority: 1},
			config.OIDCProvider{Name: "also-off", Priority: 2},
		),
	}

	for name, broker := range tests {
		t.Run(name, func(t *testing.T) {
			if provider := broker.selectProvider(); provider != nil {
				t.Errorf("selectProvider() = %s, want nil", provider.Name)
			}
		})
	}
}

func assertOrder(t *testing.T, broker *Broker, want []string) {
	t.Helper()

	candidates := broker.loginProviders()
	got := make([]string, len(candidates))
	for i, candidate := range candidates {
		got[i] = candidate.Name
	}

	if len(got) != len(want) {
		t.Fatalf("loginProviders() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("loginProviders() = %v, want %v", got, want)
		}
	}
}
