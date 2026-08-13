package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	// homeDir stands in for /home. A test that cares whether a login key was
	// provisioned has to look at the filesystem, since that is the only place the
	// answer is recorded.
	homeDir string
	// auditPath is the JSON-lines file the broker's audit logger writes to.
	auditPath string
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

	// A real, file-backed audit logger rather than a disabled one. The audit
	// record is part of what a device flow produces, and the defect in #153 was a
	// record with the wrong contents — which a disabled logger cannot show.
	// "sync" writes on the calling goroutine, so nothing is left buffered by the
	// time the flow returns and no Start()/Stop() pair is needed.
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := security.NewAuditLogger(config.AuditConfig{
		Enabled:          true,
		Outputs:          []config.AuditOutput{{Type: "file", Path: auditPath}},
		OverflowStrategy: "sync",
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = auditLogger.Stop() })

	keyManager := sshpkg.NewKeyManager(t.TempDir())
	// The happy path generates a login key; 2048 bits keeps that off the
	// critical path of a test that is about polling.
	keyManager.SetKeySize(2048)

	homeDir := t.TempDir()

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
		authorizedKeysManager: sshpkg.NewAuthorizedKeysManager(homeDir),
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
		// A session ID of the shape the broker actually mints: 32 random bytes,
		// hex-encoded. It matters that this is not a plausible login name — the key
		// store is keyed by it, and the bug in #152 was a store that validated it
		// as a POSIX username. A friendlier "sess-poll-test" passes that check by
		// accident and hides the defect.
		ID:           "9d1c6f0e5b4a3827160f9e8d7c6b5a493827160f9e8d7c6b5a4938271605f4e3d",
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

	return &pollTestEnv{
		broker:    broker,
		provider:  provider,
		idp:       idp,
		session:   session,
		flow:      flow,
		homeDir:   homeDir,
		auditPath: auditPath,
	}
}

// auditEvents returns every event the flow recorded, in the order it wrote them.
// A run that recorded nothing yields nil rather than an error, so a test can
// assert on an absence.
func (e *pollTestEnv) auditEvents(t *testing.T) []security.AuditEvent {
	t.Helper()

	data, err := os.ReadFile(e.auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("reading the audit log: %v", err)
	}

	var events []security.AuditEvent
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event security.AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("audit line %q is not a valid event: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

// auditEvent returns the one event of the given type, failing if the run did not
// record exactly one.
func (e *pollTestEnv) auditEvent(t *testing.T, eventType string) security.AuditEvent {
	t.Helper()

	var matched []security.AuditEvent
	var seen []string
	for _, event := range e.auditEvents(t) {
		seen = append(seen, event.EventType)
		if event.EventType == eventType {
			matched = append(matched, event)
		}
	}
	if len(matched) != 1 {
		t.Fatalf("audit log has %d %q event(s), want exactly 1; it recorded %v",
			len(matched), eventType, seen)
	}
	return matched[0]
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

// The regression gate for #153: the record of a successful login has to name the
// identity that login resolved to.
//
// The poll loop clones the session before mutating it, and writes the email and
// groups it got from the provider onto the clone. The success event was built from
// the original, so it went to the audit trail with email "" and groups null on
// every login — while the *denial* events, built from the provider's user info
// directly, carried the identity correctly. An operator reviewing the trail could
// see who was refused but not who got in.
func TestSuccessAuditCarriesResolvedIdentity(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.Pending, testoidc.Grant)

	env.run(t)

	if session := env.activeSession(); session == nil || !session.IsActive {
		t.Fatal("the flow did not complete, so there is no success record to check")
	}

	event := env.auditEvent(t, "authentication_successful")

	// The two fields that were empty. They are the point of the event: user_id is
	// the local account, but the email and groups are the federated identity that
	// account was mapped from.
	if event.Email != "testuser@example.org" {
		t.Errorf("audited email = %q, want the identity the flow resolved (#153)", event.Email)
	}
	if len(event.Groups) != 1 || event.Groups[0] != "researchers" {
		t.Errorf("audited groups = %v, want [researchers] from the claims (#153)", event.Groups)
	}

	// And the rest of the record still has to be right.
	if event.UserID != "testuser" {
		t.Errorf("audited user_id = %q, want %q", event.UserID, "testuser")
	}
	if event.SessionID != env.session.ID {
		t.Errorf("audited session_id = %q, want %q", event.SessionID, env.session.ID)
	}
	if event.Provider != "testidp" {
		t.Errorf("audited provider = %q, want %q", event.Provider, "testidp")
	}
	if !event.Success {
		t.Error("the success event is recorded with success=false")
	}
}

// The counterpart: a refusal is recorded with the identity too. This passed before
// #153 was fixed and must keep passing after, since the fix touches the shared
// clone the success path reads from.
func TestDenialAuditCarriesResolvedIdentity(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.AccessDenied)

	env.run(t)

	event := env.auditEvent(t, "device_authorization_failed")
	if event.Success {
		t.Error("a refused authorization is recorded with success=true")
	}
	if event.UserID != "testuser" {
		t.Errorf("audited user_id = %q, want %q", event.UserID, "testuser")
	}
	if event.SessionID != env.session.ID {
		t.Errorf("audited session_id = %q, want %q", event.SessionID, env.session.ID)
	}
	if event.ErrorCode == "" {
		t.Error("a refusal is recorded with no error code, so the trail does not say why")
	}
}

// The regression gate for #152: a granted device flow must actually provision the
// login key, which is the whole point of the broker.
//
// This failed against the code that keyed the on-disk key store by session ID but
// validated that ID as a POSIX login name: SaveKey refused every real session ID,
// the error was only logged, and the login carried on and was audited as a
// success — so nothing but an end-to-end run noticed that no key was ever written.
func TestDeviceFlowProvisionsLoginKey(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.Grant)

	env.run(t)

	session := env.activeSession()
	if session == nil {
		t.Fatal("session was removed even though the provider granted the token")
	}
	if session.SSHKeyID == "" {
		t.Fatal("session has no SSHKeyID: no login key was provisioned (#152)")
	}
	if session.SSHKeyID != session.ID {
		t.Errorf("SSHKeyID = %q, want the session ID %q", session.SSHKeyID, session.ID)
	}

	// The pair has to be retrievable by the ID the session points at, or nothing
	// can revoke it later.
	stored, err := env.broker.keyManager.LoadKey(session.SSHKeyID)
	if err != nil {
		t.Fatalf("LoadKey(%q): %v", session.SSHKeyID, err)
	}
	if len(stored.PrivateKey) == 0 {
		t.Error("stored key pair has no private key")
	}

	// And it has to be authorized for the local account, in the user's own file,
	// exactly once.
	authorizedKeys := filepath.Join(env.homeDir, session.UserID, ".ssh", "authorized_keys")
	data, err := os.ReadFile(authorizedKeys)
	if err != nil {
		t.Fatalf("reading %s: %v", authorizedKeys, err)
	}
	if got := strings.Count(string(data), "@oidc-pam-"); got != 1 {
		t.Errorf("authorized_keys has %d oidc-pam key(s), want exactly 1:\n%s", got, data)
	}
	if !strings.Contains(string(data), session.UserID+"@oidc-pam-") {
		t.Errorf("the authorized key is not commented for %q:\n%s", session.UserID, data)
	}
}
