package auth

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/internal/testoidc"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
	sshpkg "github.com/scttfrdmn/oidc-pam/pkg/ssh"
)

// These tests drive Broker.pollDeviceAuthorization against a real in-process
// issuer, because the bug they exist for (#150) lived precisely in the gap
// between the two: the provider reported a pending authorization as
// "token error: authorization_pending", the poll loop compared the error string
// against "authorization_pending", the comparison never matched, and so the
// first pending poll — which is the *normal* answer to every poll before the
// user finishes in the browser — took the deny path and deleted the session.
// The device flow could not complete at all, roughly five seconds after the
// verification URL was shown.
//
// Nothing short of an end-to-end loop catches that. A unit test on the provider
// would have passed (it returned the right code), and a unit test on the loop
// with a hand-built error would have passed too (whichever spelling the test
// chose would have been the one the loop compared against). What was untested
// was the two halves agreeing.

const testPollUnit = 10 * time.Millisecond

// pollTestEnv is a broker wired to an in-process issuer, plus a started device
// flow and the pending session that goes with it.
type pollTestEnv struct {
	broker   *Broker
	provider *OIDCProvider
	idp      *testoidc.Server
	session  *Session
	flow     *DeviceFlow
}

func newPollTestEnv(t *testing.T) *pollTestEnv {
	t.Helper()

	const clientID = "oidc-pam-test-client"
	idp := testoidc.New(t, clientID)

	secCfg := config.SecurityConfig{
		VerifyAudience:     true,
		TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
	provider, err := NewOIDCProvider(config.OIDCProvider{
		Name:            "testidp",
		Issuer:          idp.Issuer(),
		ClientID:        clientID,
		Scopes:          []string{"openid", "profile", "email"},
		EnabledForLogin: true,
		UserMapping: config.UserMapping{
			UsernameClaim: "preferred_username",
			EmailClaim:    "email",
			GroupsClaim:   "groups",
		},
	}, secCfg)
	if err != nil {
		t.Fatalf("NewOIDCProvider against the in-process issuer: %v", err)
	}

	auditLogger, err := security.NewAuditLogger(config.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	keyManager := sshpkg.NewKeyManager(t.TempDir())
	// The happy path generates a login key; 2048 bits keeps that off the
	// critical path of a test that is about polling.
	keyManager.SetKeySize(2048)

	broker := &Broker{
		config: &config.Config{
			Authentication: config.AuthenticationConfig{
				TokenLifetime:    time.Hour,
				RefreshThreshold: 15 * time.Minute,
			},
			Security: secCfg,
		},
		providers:             map[string]*OIDCProvider{"testidp": provider},
		tokenManager:          newTestTokenManager(t),
		policyEngine:          &PolicyEngine{},
		auditLogger:           auditLogger,
		sessions:              make(map[string]*Session),
		keyManager:            keyManager,
		authorizedKeysManager: sshpkg.NewAuthorizedKeysManager(t.TempDir()),
		stopChan:              make(chan struct{}),
		pollIntervalUnit:      testPollUnit,
	}

	// A real StartDeviceFlow, so the device code and nonce the token endpoint
	// is asked about are the ones the provider actually negotiated.
	flow, err := provider.StartDeviceFlow(&AuthRequest{UserID: "testuser", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if flow.PollingInterval != minPollingInterval {
		t.Fatalf("polling interval = %d, want the RFC 8628 floor of %d", flow.PollingInterval, minPollingInterval)
	}

	session := &Session{
		ID:           "sess-poll-test",
		UserID:       "testuser",
		Provider:     "testidp",
		LoginType:    "ssh",
		CreatedAt:    time.Now(),
		ExpiresAt:    flow.ExpiresAt,
		LastAccessed: time.Now(),
		SourceIP:     "192.0.2.10",
		IsActive:     false,
	}
	broker.setSession(session)

	return &pollTestEnv{broker: broker, provider: provider, idp: idp, session: session, flow: flow}
}

// run drives the poll loop to completion and returns how long it took.
// pollDeviceAuthorization is only ever started as a tracked goroutine, so the
// bookkeeping it unwinds has to be set up here too.
func (e *pollTestEnv) run(t *testing.T) time.Duration {
	t.Helper()

	e.broker.wg.Add(1)
	atomic.AddInt64(&e.broker.pendingFlows, 1)

	started := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.broker.pollDeviceAuthorization(e.session, e.provider, e.flow)
	}()

	select {
	case <-done:
		return time.Since(started)
	case <-time.After(30 * time.Second):
		close(e.broker.stopChan) // let the goroutine exit rather than leak
		t.Fatal("pollDeviceAuthorization never returned")
		return 0
	}
}

// activeSession is the session as the broker holds it, or nil if the loop
// removed it. The loop replaces the map entry with a clone rather than mutating
// in place, so re-reading through the broker is the only way to see the result.
func (e *pollTestEnv) activeSession() *Session {
	return e.broker.getSession(e.session.ID)
}

// The regression gate for #150: a flow that answers authorization_pending twice
// before granting must reach an active session. On the broken code the loop
// exited during the first poll, so this fails there with the session gone.
func TestDeviceFlowCompletesAfterAuthorizationPending(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.Pending, testoidc.Pending, testoidc.Grant)

	env.run(t)

	if polls := env.idp.Polls(); polls != 3 {
		t.Errorf("token endpoint saw %d polls, want 3 (two pending, then the grant)", polls)
	}

	session := env.activeSession()
	if session == nil {
		t.Fatal("session was removed: a pending authorization was treated as a failure (#150)")
	}
	if !session.IsActive {
		t.Error("session is still inactive after the provider granted the token")
	}
	if session.Email != "testuser@example.org" {
		t.Errorf("session email = %q, want the value from the ID token claims", session.Email)
	}
	if len(session.Groups) != 1 || session.Groups[0] != "researchers" {
		t.Errorf("session groups = %v, want [researchers] from the claims", session.Groups)
	}

	// The tokens must have reached the encrypted store, since that is what the
	// session's TokenID points at.
	if session.TokenID == "" {
		t.Fatal("session has no TokenID, so its tokens were never stored")
	}
	stored, err := env.broker.tokenManager.GetToken(session.TokenID)
	if err != nil {
		t.Fatalf("GetToken(%q): %v", session.TokenID, err)
	}
	if stored.RefreshToken == "" {
		t.Error("stored token has no refresh token")
	}
}

// slow_down is the other non-terminal code. The flow must survive it *and* poll
// more slowly afterwards — RFC 8628 §3.5 requires the client to add 5 s to its
// interval each time, and a provider that sends it is usually rate-limiting.
func TestDeviceFlowHonoursSlowDown(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.SlowDown, testoidc.SlowDown, testoidc.SlowDown, testoidc.Grant)

	elapsed := env.run(t)

	if polls := env.idp.Polls(); polls != 4 {
		t.Errorf("token endpoint saw %d polls, want 4 (three slow_down, then the grant)", polls)
	}
	if session := env.activeSession(); session == nil || !session.IsActive {
		t.Fatal("slow_down ended the flow instead of slowing it down")
	}

	// Intervals in units: 5, then 10, 15, 20 as each slow_down adds
	// slowDownIncrement — 50 units to the grant, against 20 if the increase
	// were ignored. The bound is deliberately loose and one-sided: a slow
	// machine only ever pushes the measurement up.
	want := 40 * testPollUnit
	if elapsed < want {
		t.Errorf("four polls took %v, want at least %v — the interval did not grow by %d s per slow_down",
			elapsed, want, slowDownIncrement)
	}
}

// The terminal codes must stay terminal. Continuing to poll after access_denied
// would leave a pending session behind and hammer the provider.
func TestDeviceFlowStopsOnTerminalErrors(t *testing.T) {
	for _, outcome := range []testoidc.Outcome{testoidc.AccessDenied, testoidc.ExpiredToken} {
		t.Run(string(outcome), func(t *testing.T) {
			env := newPollTestEnv(t)
			env.idp.Script(testoidc.Pending, outcome)

			env.run(t)

			if polls := env.idp.Polls(); polls != 2 {
				t.Errorf("token endpoint saw %d polls, want 2 (one pending, then %s)", polls, outcome)
			}
			if session := env.activeSession(); session != nil {
				t.Errorf("session survived %s (IsActive=%v); a refused authorization must remove it",
					outcome, session.IsActive)
			}
		})
	}
}

// With the pending path fixed, the device code's own expiry is what bounds the
// flow. It has to actually fire, or a never-completed login leaks a goroutine
// and a pending session for as long as the broker runs.
func TestDeviceFlowEndsAtDeviceCodeExpiry(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.Pending) // pending forever

	// Long enough for several polls, short enough not to slow the suite down.
	env.flow.ExpiresAt = time.Now().Add(20 * testPollUnit)
	env.session.ExpiresAt = env.flow.ExpiresAt
	env.broker.setSession(env.session)

	env.run(t)

	if polls := env.idp.Polls(); polls < 2 {
		t.Errorf("token endpoint saw %d polls before the deadline, want at least 2 "+
			"(a pending answer must not end the flow)", polls)
	}
	if session := env.activeSession(); session != nil {
		t.Error("session survived the device code's expiry")
	}
}

// Stopping the broker must abandon in-flight flows rather than keep polling a
// provider until the device code expires.
func TestDeviceFlowStopsWithTheBroker(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.Pending)

	env.broker.wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		env.broker.pollDeviceAuthorization(env.session, env.provider, env.flow)
	}()

	// Let it poll at least once so it is genuinely mid-flow.
	time.Sleep(10 * testPollUnit)
	close(env.broker.stopChan)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pollDeviceAuthorization ignored stopChan")
	}
}

// tokenEndpointError is the seam #150 turned on: the two non-terminal codes have
// to be recognisable by identity, not by the shape of a formatted string, while
// the message the audit log records stays what it was.
func TestTokenEndpointError(t *testing.T) {
	cases := []struct {
		code     string
		sentinel error
		message  string
	}{
		{"authorization_pending", ErrAuthorizationPending, "token error: authorization_pending"},
		{"slow_down", ErrSlowDown, "token error: slow_down"},
		{"access_denied", nil, "token error: access_denied"},
		{"expired_token", nil, "token error: expired_token"},
	}

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			err := tokenEndpointError(tc.code)
			if err.Error() != tc.message {
				t.Errorf("message = %q, want %q", err.Error(), tc.message)
			}

			// Every terminal code must match neither sentinel, or the loop
			// would poll forever on a denial.
			for _, sentinel := range []error{ErrAuthorizationPending, ErrSlowDown} {
				want := errors.Is(sentinel, tc.sentinel)
				if got := errors.Is(err, sentinel); got != want {
					t.Errorf("errors.Is(%v, %v) = %v, want %v", err, sentinel, got, want)
				}
			}
		})
	}

	// And wrapping must survive the layer the broker actually sees it through.
	wrapped := fmt.Errorf("failed to poll device authorization: %w", tokenEndpointError("authorization_pending"))
	if !errors.Is(wrapped, ErrAuthorizationPending) {
		t.Error("a wrapped pending error is no longer recognisable as pending")
	}
}
