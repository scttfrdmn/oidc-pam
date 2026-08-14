package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/internal/testoidc"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
)

// TestEveryRefusedLoginIsAuditedWithItsErrorCode is the acceptance gate for #218.
//
// Every branch of Authenticate that answers with a failure has to leave a record
// carrying the same error_code the client was given. Before this, a policy denial
// was audited without its code and the four other refusals were not audited at all,
// so the events an incident responder most needs — who was refused, and why — were
// the ones the broker did not keep. A user with a valid IdP account but no group
// membership could be denied on every host on the network and leave nothing behind
// to count: sshd's log does not record which OIDC identity was refused, and the
// broker's log is not the audit trail.
//
// Driven through Authenticate rather than by asserting on the helpers, because the
// defect was branches that never reached a helper at all.
func TestEveryRefusedLoginIsAuditedWithItsErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		// wantCode is asserted on both the response and the audit record: a record
		// with a different code than the client got is a trail that cannot be joined
		// to the failure the user reported.
		wantCode string
		// wantReasonHas is what the record has to say about why, since the client is
		// told only that it was refused.
		wantReasonHas string
		setup         func(t *testing.T, env *denialTestEnv)
		req           *AuthRequest
	}{
		{
			name:          "a field longer than the broker will read",
			wantCode:      "INVALID_REQUEST",
			wantReasonHas: "maximum length",
			req:           &AuthRequest{UserID: strings.Repeat("u", 257), LoginType: "ssh"},
		},
		{
			name:          "no provider is enabled for login",
			wantCode:      "NO_PROVIDER",
			wantReasonHas: "enabled_for_login",
			setup: func(_ *testing.T, env *denialTestEnv) {
				env.broker.providers = map[string]*OIDCProvider{}
			},
			req: &AuthRequest{UserID: "testuser", SourceIP: "192.0.2.10", LoginType: "ssh"},
		},
		{
			name:          "the user is at their concurrent session limit",
			wantCode:      "TOO_MANY_SESSIONS",
			wantReasonHas: "concurrent sessions",
			setup: func(_ *testing.T, env *denialTestEnv) {
				env.broker.config.Authentication.MaxConcurrentSessions = 1
				env.broker.setSession(&Session{
					ID:        "already-logged-in",
					UserID:    "testuser",
					IsActive:  true,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(time.Hour),
				})
			},
			req: &AuthRequest{UserID: "testuser", SourceIP: "192.0.2.10", LoginType: "ssh"},
		},
		{
			name:          "policy no longer allows this identity",
			wantCode:      "POLICY_DENIED",
			wantReasonHas: "ip_whitelist",
			setup: func(t *testing.T, env *denialTestEnv) {
				env.broker.config.Authentication.Policies = map[string]config.AuthenticationPolicy{
					"default": {IPWhitelist: []string{"10.0.0.0/8"}},
				}
				env.broker.policyEngine = newTestPolicyEngine(t, env.broker.config)
			},
			req: &AuthRequest{UserID: "testuser", SourceIP: "192.0.2.10", LoginType: "ssh"},
		},
		{
			name:          "the host is at its device-flow cap",
			wantCode:      "RATE_LIMITED",
			wantReasonHas: "pending device authorization flows",
			setup: func(_ *testing.T, env *denialTestEnv) {
				// (#163) A full pool refuses only a requester that already holds as many
				// unfinished logins as its largest holder does — otherwise it displaces
				// one and admits this login, which is what stops the pool being a
				// host-wide lockout. So: ninety-nine other pairs holding one each, and
				// one already held by this pair.
				for i := 0; i < 99; i++ {
					env.broker.setSession(pendingSessionFixture(
						fmt.Sprintf("other-%d", i), fmt.Sprintf("user-%d", i), "198.51.100.4"))
				}
				env.broker.setSession(pendingSessionFixture("mine", "testuser", "192.0.2.10"))
			},
			req: &AuthRequest{UserID: "testuser", SourceIP: "192.0.2.10", LoginType: "ssh"},
		},
		{
			name:          "this account and address are at their pending-flow cap",
			wantCode:      "TOO_MANY_PENDING_AUTHS",
			wantReasonHas: "awaiting device approval",
			setup: func(_ *testing.T, env *denialTestEnv) {
				for i := 0; i < defaultMaxPendingAuthsPerSource; i++ {
					env.broker.setSession(pendingSessionFixture(
						fmt.Sprintf("pending-%d", i), "testuser", "192.0.2.10"))
				}
			},
			req: &AuthRequest{UserID: "testuser", SourceIP: "192.0.2.10", LoginType: "ssh"},
		},
		{
			name:          "the account does not exist on this host",
			wantCode:      "NO_LOCAL_ACCOUNT",
			wantReasonHas: "no such local account",
			setup: func(_ *testing.T, env *denialTestEnv) {
				env.broker.config.Authentication.RequireLocalAccount = true
				env.broker.lookupLocalUID = func(string) (int, bool, error) { return 0, false, nil }
			},
			req: &AuthRequest{UserID: "testuser", SourceIP: "192.0.2.10", LoginType: "ssh"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newDenialTestEnv(t)
			if tc.setup != nil {
				tc.setup(t, env)
			}

			resp, err := env.broker.Authenticate(tc.req)
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if resp.Success {
				t.Fatalf("the request was not refused: %+v", resp)
			}
			if resp.ErrorCode != tc.wantCode {
				t.Fatalf("response error_code = %q, want %q", resp.ErrorCode, tc.wantCode)
			}

			events := auditEventsAt(t, env.auditPath)
			var denial *security.AuditEvent
			for i := range events {
				if events[i].EventType == "authentication_denied" {
					denial = &events[i]
				}
			}
			if denial == nil {
				var seen []string
				for _, e := range events {
					seen = append(seen, e.EventType)
				}
				t.Fatalf("a refused login left no authentication_denied record; the trail holds %v (#218)", seen)
			}
			if denial.ErrorCode != tc.wantCode {
				t.Errorf("audited error_code = %q, want the %q the client was given: a record that does "+
					"not carry the client's code cannot be joined to the failure the user reported",
					denial.ErrorCode, tc.wantCode)
			}
			if denial.Success {
				t.Error("the refusal is recorded with success=true")
			}
			if !strings.Contains(denial.ErrorMessage, tc.wantReasonHas) {
				t.Errorf("audited reason %q does not mention %q, so the record does not say why the "+
					"login was refused", denial.ErrorMessage, tc.wantReasonHas)
			}
		})
	}
}

// TestPolicyDenialRecordsWhatItWasDecidedOn covers the rest of what #218 asks the
// policy record to carry. The reason alone does not let an operator tell a
// deliberate denial from a risk-scoring surprise, and the risk score is not
// recoverable afterwards — it is computed from the request and the time of day.
func TestPolicyDenialRecordsWhatItWasDecidedOn(t *testing.T) {
	env := newDenialTestEnv(t)
	env.broker.config.Authentication.RiskPolicies = []config.RiskPolicy{
		// No recommendation: the reason has to name the rule that fired anyway.
		{Condition: "risk_score >= 0", Action: "DENY"},
	}
	env.broker.policyEngine = newTestPolicyEngine(t, env.broker.config)

	resp, err := env.broker.Authenticate(&AuthRequest{
		UserID:    "testuser",
		SourceIP:  "192.0.2.10",
		LoginType: "ssh",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.ErrorCode != "POLICY_DENIED" {
		t.Fatalf("error_code = %q, want POLICY_DENIED", resp.ErrorCode)
	}
	// The reason names configuration, so it stays out of the reply and lives only in
	// the trail.
	if strings.Contains(resp.ErrorMessage, "risk_score") {
		t.Errorf("the reply repeats the policy that refused it (%q); the reason is for the audit log, "+
			"not the client", resp.ErrorMessage)
	}

	var denial *security.AuditEvent
	for _, event := range auditEventsAt(t, env.auditPath) {
		if event.EventType == "authentication_denied" {
			e := event
			denial = &e
		}
	}
	if denial == nil {
		t.Fatal("the policy denial was not audited")
	}
	if !strings.Contains(denial.ErrorMessage, "risk_score >= 0") {
		t.Errorf("audited reason %q does not name the risk policy that fired, so an operator cannot "+
			"tell which rule refused the login", denial.ErrorMessage)
	}
	if denial.Provider != "testidp" {
		t.Errorf("audited provider = %q, want testidp", denial.Provider)
	}
	if len(denial.PolicyViolations) == 0 {
		t.Error("the record carries no policy_violations, so a search for denials by rule finds nothing")
	}
	if got := denial.Metadata["login_type"]; got != "ssh" {
		t.Errorf("audited login_type = %v, want ssh", got)
	}
}

// TestReachingForSomeoneElsesSessionIsAudited covers the three session verbs. Each
// already refused a caller asking about an account other than its own, and refused
// it silently — so the one thing here that is unambiguously an attack, since nobody
// reaches another user's 64-hex session ID by accident, was the least visible thing
// the broker did (#218).
func TestReachingForSomeoneElsesSessionIsAudited(t *testing.T) {
	const (
		sessionID = "3f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
		owner     = "alice"
		attacker  = "bob"
	)

	for _, tc := range []struct {
		verb string
		// refuse asserts the verb refused the caller, in whatever way that verb
		// answers: two return an AuthResponse, RevokeSession returns an error.
		refuse func(t *testing.T, b *Broker)
	}{
		{
			verb: "check_session",
			refuse: func(t *testing.T, b *Broker) {
				resp, err := b.CheckSession(sessionID, attacker)
				if err != nil {
					t.Fatalf("CheckSession: %v", err)
				}
				if resp.Success || resp.ErrorCode != "FORBIDDEN" {
					t.Fatalf("CheckSession answered another user's session: %+v", resp)
				}
			},
		},
		{
			verb: "refresh_session",
			refuse: func(t *testing.T, b *Broker) {
				resp, err := b.RefreshSession(sessionID, attacker)
				if err != nil {
					t.Fatalf("RefreshSession: %v", err)
				}
				if resp.Success || resp.ErrorCode != "FORBIDDEN" {
					t.Fatalf("RefreshSession extended another user's session: %+v", resp)
				}
			},
		},
		{
			verb: "revoke_session",
			refuse: func(t *testing.T, b *Broker) {
				if err := b.RevokeSession(sessionID, attacker); err == nil {
					t.Fatal("RevokeSession let a caller revoke another user's session")
				}
			},
		},
	} {
		t.Run(tc.verb, func(t *testing.T) {
			session := &Session{
				ID:        sessionID,
				UserID:    owner,
				IsActive:  true,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			}
			broker, auditPath := refreshTestBroker(t, refreshTestConfig(), session)

			tc.refuse(t, broker)

			// Refused, and the owner's session untouched.
			if got := broker.getSession(sessionID); got == nil {
				t.Fatalf("%s by a caller who does not own the session removed it", tc.verb)
			}

			var denial *security.AuditEvent
			for _, event := range auditEventsAt(t, auditPath) {
				if event.EventType == "session_access_denied" {
					e := event
					denial = &e
				}
			}
			if denial == nil {
				t.Fatalf("%s refused a caller reaching for another user's session and recorded nothing "+
					"(#218)", tc.verb)
			}
			if denial.UserID != attacker {
				t.Errorf("audited user_id = %q, want the caller %q", denial.UserID, attacker)
			}
			if denial.SessionID != sessionID {
				t.Errorf("audited session_id = %q, want %q", denial.SessionID, sessionID)
			}
			if got := denial.Metadata["session_owner"]; got != owner {
				t.Errorf("audited session_owner = %v, want %q: without it the record does not say whose "+
					"account was reached for", got, owner)
			}
			if got := denial.Metadata["request_type"]; got != tc.verb {
				t.Errorf("audited request_type = %v, want %q", got, tc.verb)
			}
			if denial.ErrorCode != "FORBIDDEN" {
				t.Errorf("audited error_code = %q, want FORBIDDEN", denial.ErrorCode)
			}
		})
	}
}

// denialTestEnv is a broker that can reach every deny branch of Authenticate: a real
// provider (so provider selection succeeds), a real policy engine, and a file-backed
// audit logger to read the record back out of.
type denialTestEnv struct {
	broker    *Broker
	auditPath string
}

func newDenialTestEnv(t *testing.T) *denialTestEnv {
	t.Helper()

	const clientID = "oidc-pam-test-client"
	idp := testoidc.New(t, clientID)

	secCfg := config.SecurityConfig{
		TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
	provider, err := NewOIDCProvider(config.OIDCProvider{
		Name:            "testidp",
		Issuer:          idp.Issuer(),
		ClientID:        clientID,
		Scopes:          []string{"openid", "profile", "email"},
		EnabledForLogin: true,
		UserMapping:     config.UserMapping{UsernameClaim: "preferred_username"},
	}, secCfg)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime:    time.Hour,
			RefreshThreshold: 15 * time.Minute,
		},
		Security: secCfg,
	}

	broker, auditPath := refreshTestBroker(t, cfg, &Session{
		ID:     "unrelated-session",
		UserID: "someone-else",
	})
	broker.providers = map[string]*OIDCProvider{"testidp": provider}
	broker.stopChan = make(chan struct{})
	t.Cleanup(func() { broker.wg.Wait() })

	return &denialTestEnv{broker: broker, auditPath: auditPath}
}
