package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/internal/testoidc"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// addNamedProvider gives env's broker a second login provider, on its own
// issuer, that sorts after testidp — so it serves a login only when a client asks
// for it by name.
func addNamedProvider(t *testing.T, env *denialTestEnv, name string) {
	t.Helper()

	const clientID = "oidc-pam-test-client"
	idp := testoidc.New(t, clientID)
	provider, err := NewOIDCProvider(config.OIDCProvider{
		Name:            name,
		Issuer:          idp.Issuer(),
		ClientID:        clientID,
		Scopes:          []string{"openid", "profile", "email"},
		EnabledForLogin: true,
		Priority:        9,
		UserMapping:     config.UserMapping{UsernameClaim: "preferred_username"},
	}, env.broker.config.Security)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	// testidp sets no priority, which sorts after every provider that does, so
	// give it one that keeps it the default.
	env.broker.providers["testidp"].Config.Priority = 1
	env.broker.providers[name] = provider
	// A started flow leaves a poller running, and the env's cleanup waits for it;
	// stop the broker first so that wait is not the length of a poll. Cleanups run
	// last-registered first, so this runs before that wait.
	t.Cleanup(func() { close(env.broker.stopChan) })
}

// A client that names a provider gets a device flow from that provider, not the
// default (#287), and one that names none still gets the default.
func TestANamedProviderServesTheLogin(t *testing.T) {
	for _, tc := range []struct {
		requested, want string
	}{
		{"", "testidp"},
		{"backup", "backup"},
		{"testidp", "testidp"},
	} {
		t.Run(fmt.Sprintf("provider %q", tc.requested), func(t *testing.T) {
			env := newDenialTestEnv(t)
			addNamedProvider(t, env, "backup")

			resp, err := env.broker.Authenticate(&AuthRequest{
				UserID: "testuser", SourceIP: "192.0.2.10", LoginType: "ssh", Provider: tc.requested,
			})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if !resp.RequiresDevice || resp.ErrorCode != "" {
				t.Fatalf("Authenticate did not start a device flow: error_code %q", resp.ErrorCode)
			}
			session := env.broker.getSession(resp.SessionID)
			if session == nil {
				t.Fatalf("no session %q after a started device flow", resp.SessionID)
			}
			if session.Provider != tc.want {
				t.Errorf("the login was served by %q, want %q", session.Provider, tc.want)
			}
		})
	}
}

// Policy is evaluated against the provider that serves the login, which is the one
// the client named. So a restriction scoped to that provider applies to it, and
// naming a provider is not a way out of the restrictions on the one that serves
// you (#213): the restriction below forbids every login through "backup" right
// now, and does not touch the default.
func TestANamedProviderIsJudgedByItsOwnRestrictions(t *testing.T) {
	// An allowed window that starts two hours from now and lasts one hour, so it
	// never contains the moment the test runs.
	start := time.Now().UTC().Add(2 * time.Hour)
	window := fmt.Sprintf("%02d:00-%02d:00", start.Hour(), start.Add(time.Hour).Hour())

	for _, tc := range []struct {
		requested string
		refused   bool
	}{
		{"backup", true},
		{"", false},
	} {
		t.Run(fmt.Sprintf("provider %q", tc.requested), func(t *testing.T) {
			env := newDenialTestEnv(t)
			addNamedProvider(t, env, "backup")
			env.broker.config.Authentication.TimeBasedPolicies.TimeRestrictions = []config.TimeRestriction{{
				Providers:    []string{"backup"},
				AllowedHours: window,
				Timezone:     "UTC",
			}}
			env.broker.policyEngine = newTestPolicyEngine(t, env.broker.config)

			resp, err := env.broker.Authenticate(&AuthRequest{
				UserID: "testuser", SourceIP: "192.0.2.10", LoginType: "ssh", Provider: tc.requested,
			})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if refused := resp.ErrorCode != ""; refused != tc.refused {
				t.Errorf("refused = %v (error_code %q), want %v: allowed_hours %s scoped to backup",
					refused, resp.ErrorCode, tc.refused, window)
			}
		})
	}
}
