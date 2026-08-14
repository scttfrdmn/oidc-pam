package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	// requiredGroups is what the policy engine would have resolved for this login:
	// the union of the global require_groups and every matching per-resource
	// policy's. pollDeviceAuthorization takes it as an argument rather than reading
	// config, so a test drives group enforcement by setting this (#158).
	requiredGroups []string
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
		authorizedKeysManager: testAuthorizedKeysManager(t, homeDir, "testuser", "deploy"),
		stopChan:              make(chan struct{}),
		pollIntervalUnit:      testPollUnit,
		// A fixed passwd table, so the privileged-account guard (#159) behaves the
		// same wherever the suite runs. Reading the host's real passwd would make
		// these tests depend on whether it happens to have a "testuser" and what uid
		// it gave them.
		lookupLocalUID: testLookupUID,
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
		// (#163) Every pending session the broker mints carries the channel that
		// tells its poll loop to stop, so a fixture that stands in for one has to
		// have it too.
		cancel: make(chan struct{}),
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

	started := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.broker.pollDeviceAuthorization(e.session, e.provider, e.flow, e.requiredGroups)
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
	stored, err := env.broker.tokenManager.GetToken(session.TokenID, session.UserID)
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
		env.broker.pollDeviceAuthorization(env.session, env.provider, env.flow, env.requiredGroups)
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

// TestPerPolicyRequireGroupsIsEnforced covers #158.
//
// The gate is the *config path*, not the comparison. verifyRequiredGroups was
// always correct; it was reading the wrong list. require_groups written under
// authentication.policies.<name> — the form QUICK-START.md:136-138 and
// DEPLOYMENT.md:280-297 both instruct operators to use — was collected into
// PolicyResult.RequiredGroups by applyResourcePolicies and then read by nothing,
// while the enforcement looked at the global authentication.require_groups, which
// in this configuration is empty. So the documented configuration enforced no
// groups at all and any identity the IdP would authenticate got a login.
//
// Note what this test deliberately does not do: it does not set
// Authentication.RequireGroups. That is the field the old code read, and setting it
// is what let TestVerifyRequiredGroups pass while the real path was open.
func TestPerPolicyRequireGroupsIsEnforced(t *testing.T) {
	env := newPollTestEnv(t)

	// A policy named for the resource being logged into — this host. The engine
	// matches on its own hostname rather than on req.TargetHost, which is PAM_RHOST
	// and names the *client*.
	const host = "policy-test-host"
	policyCfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			Policies: map[string]config.AuthenticationPolicy{
				host: {RequireGroups: []string{"hpc-admins"}},
			},
		},
	}
	engine := &PolicyEngine{config: policyCfg, resourceHost: host}

	result, err := engine.EvaluateRequest(&AuthRequest{
		UserID:     "testuser",
		LoginType:  "ssh",
		SourceIP:   "192.0.2.10",
		TargetHost: "some-client.example.net", // what a client actually sends
	}, "")
	if err != nil {
		t.Fatalf("EvaluateRequest: %v", err)
	}
	if len(result.RequiredGroups) != 1 || result.RequiredGroups[0] != "hpc-admins" {
		t.Fatalf("policy resolved RequiredGroups = %v, want [hpc-admins] from the per-policy config", result.RequiredGroups)
	}

	// Now the login. The issuer's identity is in "researchers" and no other group,
	// so the requirement cannot be satisfied.
	env.requiredGroups = result.RequiredGroups
	env.idp.Script(testoidc.Grant)

	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("the session survived a login that satisfies no required group: %+v", session)
	}

	event := env.auditEvent(t, "authentication_denied")
	if event.ErrorCode != "GROUP_DENIED" {
		t.Errorf("denial recorded with error_code %q, want GROUP_DENIED", event.ErrorCode)
	}
	if event.Success {
		t.Error("the denial event is recorded with success=true")
	}
	for _, e := range env.auditEvents(t) {
		if e.EventType == "authentication_successful" {
			t.Fatal("a login that satisfies no required group was recorded as successful (#158)")
		}
	}

	// And no credential was left behind for it.
	authorizedKeys := filepath.Join(env.homeDir, env.session.UserID, ".ssh", "authorized_keys")
	if data, err := os.ReadFile(authorizedKeys); err == nil && strings.Contains(string(data), "@oidc-pam-") {
		t.Errorf("a refused login installed a login key:\n%s", data)
	}
}

// TestResourcePolicyMatchesTheResourceNotTheClient covers the other half of #158:
// policies were matched against req.TargetHost, which both clients populate from
// PAM_RHOST — the address the user is connecting *from*. A policy named
// "production" therefore only ever matched a client literally named "production",
// so the whole policies: block never fired for anyone.
func TestResourcePolicyMatchesTheResourceNotTheClient(t *testing.T) {
	policyCfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			Policies: map[string]config.AuthenticationPolicy{
				"production": {RequireGroups: []string{"prod-admins"}},
			},
		},
	}

	tests := []struct {
		name         string
		resourceHost string
		targetHost   string
		wantGroups   bool
	}{
		{"resource host matches the policy name", "production", "laptop.example.net", true},
		{"resource host in the policy's domain", "api.production.example.com", "laptop.example.net", true},
		{"client host matching the policy name does not", "some-host", "production", false},
		{"neither matches", "some-host", "laptop.example.net", false},
		{"no hostname resolved, so nothing matches", "", "production", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := &PolicyEngine{config: policyCfg, resourceHost: tc.resourceHost}
			result, err := engine.EvaluateRequest(&AuthRequest{
				UserID: "testuser", LoginType: "ssh", TargetHost: tc.targetHost,
			}, "")
			if err != nil {
				t.Fatalf("EvaluateRequest: %v", err)
			}
			got := len(result.RequiredGroups) > 0
			if got != tc.wantGroups {
				t.Errorf("RequiredGroups = %v, want a requirement: %v", result.RequiredGroups, tc.wantGroups)
			}
		})
	}
}

// TestQuickStartConfigEnforcesItsRequiredGroups is the acceptance test for #158:
// the exact configuration QUICK-START.md hands a first-time operator, loaded
// through the real config loader, must deny a user who is in none of the groups it
// names.
//
// This is the test that mattered. The two tests above construct a config.Config in
// Go, so they prove the engine and the enforcement agree; they cannot prove that
// the YAML in the docs reaches the engine at all. It did not: `policies.default`
// names no host, so before the DefaultPolicyName catch-all this config matched
// nothing, resolved no required groups, and admitted every identity the IdP would
// authenticate.
func TestQuickStartConfigEnforcesItsRequiredGroups(t *testing.T) {
	// Verbatim from QUICK-START.md:138-146 — the authentication block a new
	// operator is told to write. If this literal changes in the docs, change it
	// here too, and expect this test to tell you if it stopped enforcing anything.
	// (#170) It said `session_duration`, which is not a field of a policy; the
	// loader dropped it in silence then and refuses it now, so the doc says
	// max_session_duration.
	// (#212) It also said `audit_level: "standard"`, which nothing has ever read.
	// The broker now refuses to start on it rather than reporting an audit level it
	// does not apply, so the doc no longer offers it.
	const quickStartAuth = `
authentication:
  token_lifetime: "8h"
  policies:
    default:
      require_groups: ["users"]
      max_session_duration: "8h"
`
	configPath := filepath.Join(t.TempDir(), "broker.yaml")
	if err := os.WriteFile(configPath, []byte(quickStartAuth), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig on the QUICK-START configuration: %v", err)
	}
	if got := cfg.Authentication.Policies["default"].RequireGroups; len(got) != 1 || got[0] != "users" {
		t.Fatalf("loader read policies.default.require_groups as %v, want [users]", got)
	}
	// The global key stays empty: that is the whole point. It is what the old
	// enforcement read.
	if len(cfg.Authentication.RequireGroups) != 0 {
		t.Fatalf("authentication.require_groups = %v, want empty; this config sets only the per-policy form",
			cfg.Authentication.RequireGroups)
	}

	// A real engine, so the host resolution and the catch-all both run for real.
	engine, err := NewPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	defer engine.Close()

	result, err := engine.EvaluateRequest(&AuthRequest{
		UserID:     "testuser",
		LoginType:  "ssh",
		SourceIP:   "192.0.2.10",
		TargetHost: "some-client.example.net",
	}, "")
	if err != nil {
		t.Fatalf("EvaluateRequest: %v", err)
	}
	if len(result.RequiredGroups) != 1 || result.RequiredGroups[0] != "users" {
		t.Fatalf("the QUICK-START config resolved RequiredGroups = %v, want [users]; "+
			"a policies.default block that resolves nothing enforces nothing (#158)", result.RequiredGroups)
	}

	// And the login it governs is refused: the issuer's identity is in
	// "researchers", not "users".
	env := newPollTestEnv(t)
	env.requiredGroups = result.RequiredGroups
	env.idp.Script(testoidc.Grant)

	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("the QUICK-START configuration admitted a user in none of its require_groups: %+v", session)
	}
	if event := env.auditEvent(t, "authentication_denied"); event.ErrorCode != "GROUP_DENIED" {
		t.Errorf("denial recorded with error_code %q, want GROUP_DENIED", event.ErrorCode)
	}
}

// TestAbsentUsernameClaimRefusedOnTheRealPath drives #164 through the whole device
// flow: an approved authorization whose token does not carry the configured
// username_claim must leave no session and no SSH key, and be audited as
// USERNAME_CLAIM_MISSING naming the claim that was configured and missing.
//
// The scenario is an IdP that stopped returning preferred_username — a scope change,
// a claim-mapper edit, a tenant migration — while `sub` is a login name, as it is on
// LDAP/AD-backed and self-hosted IdPs. Here `sub` happens to equal the local account
// being logged into, so the deleted fallback bound it and the login was approved on a
// claim the operator never chose. The end-to-end path is what shows the consequence:
// on the broken code this run produces an active session and an installed key.
func TestAbsentUsernameClaimRefusedOnTheRealPath(t *testing.T) {
	// The provider is configured for preferred_username, as newPollTestEnv and every
	// shipped provider config are. testuser is uid 1500, so the privileged-account
	// guard is not what refuses this.
	claimsWithoutPreferredUsername := map[string]any{
		"sub":    "testuser",
		"email":  "testuser@example.org",
		"groups": []string{"researchers"},
	}

	env := newPollTestEnv(t)
	env.idp.SetClaims(claimsWithoutPreferredUsername)
	env.idp.Script(testoidc.Grant)

	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("a login was activated with no preferred_username claim in the token, "+
			"on the value of sub instead (#164): %+v", session)
	}

	event := env.auditEvent(t, "authentication_denied")
	if event.ErrorCode != "USERNAME_CLAIM_MISSING" {
		t.Errorf("denial recorded with error_code %q, want USERNAME_CLAIM_MISSING "+
			"(nothing was wrong with the identity; the configured claim never arrived)", event.ErrorCode)
	}
	if !strings.Contains(event.ErrorMessage, "preferred_username") {
		t.Errorf("the audited denial does not name the claim that was configured and missing: %q",
			event.ErrorMessage)
	}
	for _, e := range env.auditEvents(t) {
		if e.EventType == "authentication_successful" {
			t.Fatal("a login with no configured username_claim in the token was recorded as successful (#164)")
		}
	}

	// No credential of either kind: nothing in the key store, nothing authorized.
	if _, err := env.broker.keyManager.LoadKey(env.session.ID); err == nil {
		t.Error("a refused login left a key pair in the key store")
	}
	authorizedKeys := filepath.Join(env.homeDir, env.session.UserID, ".ssh", "authorized_keys")
	if data, err := os.ReadFile(authorizedKeys); err == nil && strings.Contains(string(data), "@oidc-pam-") {
		t.Errorf("a refused login installed a login key:\n%s", data)
	}

	// And the deployment the fix does not break: an operator whose IdP puts the login
	// name in `sub` configures that, and the very same token is bound.
	explicit := newPollTestEnv(t)
	explicit.provider.Config.UserMapping.UsernameClaim = "sub"
	explicit.idp.SetClaims(claimsWithoutPreferredUsername)
	explicit.idp.Script(testoidc.Grant)

	explicit.run(t)

	if session := explicit.activeSession(); session == nil || !session.IsActive {
		t.Error("username_claim: sub did not bind an identity whose sub is the local account")
	}
}

// TestAllowedGroupsDenyTheLogin is the acceptance gate for #166: a user in none of
// a provider's allowed_groups must be refused, not admitted with a trimmed group
// list.
//
// The old code applied the allowlist inside claim extraction, where the only thing
// it could do was drop groups. An identity in none of the allowed groups therefore
// arrived at the enforcement point with Groups == nil — which
// verifyRequiredGroups happily accepts when require_groups is empty, as it is in
// every shipped config — and got a session and a login key. This has to run through
// the poll loop for the same reason #158 did: the check was never the problem, its
// position on the login path was.
func TestAllowedGroupsDenyTheLogin(t *testing.T) {
	env := newPollTestEnv(t)

	// The issuer's identity is in "researchers" and nothing else, and
	// require_groups is deliberately left empty: allowed_groups alone has to
	// refuse this login.
	env.provider.Config.UserMapping.AllowedGroups = []string{"hpc-admins"}
	env.idp.Script(testoidc.Grant)

	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("a user in none of the allowed_groups was authenticated: %+v", session)
	}

	event := env.auditEvent(t, "authentication_denied")
	if event.ErrorCode != "GROUP_NOT_ALLOWED" {
		t.Errorf("denial recorded with error_code %q, want GROUP_NOT_ALLOWED "+
			"(nothing was missing from a required set; the identity is outside the permitted one)",
			event.ErrorCode)
	}
	if event.Success {
		t.Error("the denial event is recorded with success=true")
	}
	// The record has to name what the identity actually held, or an operator cannot
	// tell which group to add. The old projection would have emptied this.
	if len(event.Groups) != 1 || event.Groups[0] != "researchers" {
		t.Errorf("audited groups = %v, want [researchers] — the groups the identity has, "+
			"not the ones that survived a filter", event.Groups)
	}
	for _, e := range env.auditEvents(t) {
		if e.EventType == "authentication_successful" {
			t.Fatal("a user in none of the allowed_groups was recorded as a successful login (#166)")
		}
	}

	authorizedKeys := filepath.Join(env.homeDir, env.session.UserID, ".ssh", "authorized_keys")
	if data, err := os.ReadFile(authorizedKeys); err == nil && strings.Contains(string(data), "@oidc-pam-") {
		t.Errorf("a refused login installed a login key:\n%s", data)
	}
}

// The other half of #166's semantics: allowed_groups is a gate, so a user who is in
// one of the allowed groups gets in — and keeps every group the IdP gave them.
// Trimming the list here would leave the session, the audit trail and any
// require_groups check downstream reasoning about an identity the IdP never
// asserted.
func TestAllowedGroupsAdmitAMemberWithAllItsGroups(t *testing.T) {
	env := newPollTestEnv(t)

	env.idp.SetClaims(map[string]any{
		"sub":                "test-subject",
		"preferred_username": "testuser",
		"email":              "testuser@example.org",
		"groups":             []string{"researchers", "hpc-users"},
	})
	// Case-insensitively matching one of the two is enough; the allowlist is a
	// disjunction, and it does not have to name "hpc-users" for that group to
	// survive.
	env.provider.Config.UserMapping.AllowedGroups = []string{"Researchers"}
	env.idp.Script(testoidc.Grant)

	env.run(t)

	session := env.activeSession()
	if session == nil || !session.IsActive {
		t.Fatal("a member of an allowed group was refused")
	}
	if len(session.Groups) != 2 || session.Groups[0] != "researchers" || session.Groups[1] != "hpc-users" {
		t.Errorf("session groups = %v, want [researchers hpc-users]: allowed_groups gates the login, "+
			"it does not filter the claim (#166)", session.Groups)
	}
}

// An unset allowlist restricts nothing. This is the shipped default and what every
// deployment that has never set the key relies on, so it is worth an explicit gate
// rather than an inference from the other tests passing.
func TestEmptyAllowedGroupsRestrictNothing(t *testing.T) {
	env := newPollTestEnv(t)
	env.provider.Config.UserMapping.AllowedGroups = nil
	env.provider.Config.UserMapping.AllowedRoles = nil
	env.idp.Script(testoidc.Grant)

	env.run(t)

	if session := env.activeSession(); session == nil || !session.IsActive {
		t.Error("an empty allowed_groups refused a login; empty means unrestricted")
	}
}

// allowed_roles is the same gate over a different claim, and it was the same defect.
func TestAllowedRolesDenyTheLogin(t *testing.T) {
	env := newPollTestEnv(t)

	env.provider.Config.UserMapping.RolesClaim = "roles"
	env.provider.Config.UserMapping.AllowedRoles = []string{"cluster-admin"}
	env.idp.SetClaims(map[string]any{
		"sub":                "test-subject",
		"preferred_username": "testuser",
		"email":              "testuser@example.org",
		"groups":             []string{"researchers"},
		"roles":              []string{"guest"},
	})
	env.idp.Script(testoidc.Grant)

	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("a user holding none of the allowed_roles was authenticated: %+v", session)
	}
	if event := env.auditEvent(t, "authentication_denied"); event.ErrorCode != "GROUP_NOT_ALLOWED" {
		t.Errorf("denial recorded with error_code %q, want GROUP_NOT_ALLOWED", event.ErrorCode)
	}
}

// require_groups and allowed_groups now meet in one function, so the composition of
// the two has to be pinned: each refuses on its own, each refusal keeps its own
// error code, and satisfying one does not excuse the other.
func TestRequireGroupsAndAllowedGroupsCompose(t *testing.T) {
	tests := []struct {
		name          string
		required      []string
		allowed       []string
		wantSession   bool
		wantErrorCode string
	}{
		{
			name:        "satisfies both",
			required:    []string{"researchers"},
			allowed:     []string{"researchers"},
			wantSession: true,
		},
		{
			// In an allowed group, but missing a group the policy demands.
			name:          "allowed but not required",
			required:      []string{"hpc-admins"},
			allowed:       []string{"researchers"},
			wantErrorCode: "GROUP_DENIED",
		},
		{
			// Holds everything require_groups asks for and is still outside the
			// permitted set. This is the case the old code could not express at all.
			name:          "required but not allowed",
			required:      []string{"researchers"},
			allowed:       []string{"hpc-admins"},
			wantErrorCode: "GROUP_NOT_ALLOWED",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newPollTestEnv(t)
			env.requiredGroups = tc.required
			env.provider.Config.UserMapping.AllowedGroups = tc.allowed
			env.idp.Script(testoidc.Grant)

			env.run(t)

			session := env.activeSession()
			if tc.wantSession {
				if session == nil || !session.IsActive {
					t.Fatal("the login was refused although it satisfies both group settings")
				}
				return
			}
			if session != nil {
				t.Errorf("the session survived a refused login: %+v", session)
			}
			if event := env.auditEvent(t, "authentication_denied"); event.ErrorCode != tc.wantErrorCode {
				t.Errorf("denial recorded with error_code %q, want %q", event.ErrorCode, tc.wantErrorCode)
			}
		})
	}
}

// TestPrivilegedAccountRefusedOnTheRealPath drives #159 through the whole device
// flow, not just the binding function: a completed, approved authorization whose
// identity exactly matches a privileged local account must still be refused, leave
// no session, install no key, and be audited as PRIVILEGED_ACCOUNT_DENIED rather
// than as an identity mismatch.
//
// The unit tests call verifyIdentityBinding directly. This one proves the poll loop
// reaches it and acts on what it returns, which is where #120 showed the wiring can
// be wrong even when the check is right.
func TestPrivilegedAccountRefusedOnTheRealPath(t *testing.T) {
	// uid 400 in testPasswd. Nothing about this identity is wrong except the
	// account it wants to be: the claim matches exactly.
	const account = "deploy"

	env := newPollTestEnv(t)
	env.session.UserID = account
	env.idp.SetClaims(map[string]any{
		"sub":                "sub-deploy",
		"preferred_username": account,
		"email":              account + "@example.org",
		"groups":             []string{"researchers"},
	})
	env.idp.Script(testoidc.Grant)

	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("an OIDC login was activated for privileged account %q: %+v", account, session)
	}

	event := env.auditEvent(t, "authentication_denied")
	if event.ErrorCode != "PRIVILEGED_ACCOUNT_DENIED" {
		t.Errorf("denial recorded with error_code %q, want PRIVILEGED_ACCOUNT_DENIED "+
			"(the identity matched; the account is what was refused)", event.ErrorCode)
	}
	for _, e := range env.auditEvents(t) {
		if e.EventType == "authentication_successful" {
			t.Fatal("a login to a privileged local account was recorded as successful (#159)")
		}
	}

	authorizedKeys := filepath.Join(env.homeDir, account, ".ssh", "authorized_keys")
	if data, err := os.ReadFile(authorizedKeys); err == nil && strings.Contains(string(data), "@oidc-pam-") {
		t.Errorf("a refused privileged login installed a login key:\n%s", data)
	}

	// And with the account explicitly allowed, the same flow succeeds — the guard is
	// an override, not a wall.
	allowed := newPollTestEnv(t)
	allowed.session.UserID = account
	allowed.broker.config.Authentication.AllowPrivilegedAccounts = []string{account}
	allowed.idp.SetClaims(map[string]any{
		"sub":                "sub-deploy",
		"preferred_username": account,
		"email":              account + "@example.org",
		"groups":             []string{"researchers"},
	})
	allowed.idp.Script(testoidc.Grant)

	allowed.run(t)

	if session := allowed.activeSession(); session == nil {
		t.Error("allow_privileged_accounts did not permit the login it names")
	}
}
