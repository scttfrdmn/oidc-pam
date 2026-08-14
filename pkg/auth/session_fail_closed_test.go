package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/internal/testoidc"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
)

// TestDeviceFlowWillNotActivateASessionThatIsGone is the acceptance gate for #217.
//
// A device flow runs for up to its whole lifetime — ten minutes with the shipped
// providers — and during that window the session it belongs to can be revoked by an
// operator (`oidc-admin`, RevokeSession) or swept for expiry. The completion path
// then wrote IsActive: true into the session map unconditionally, which put the
// revoked session back as a fully active one with an SSH key installed in the
// account's authorized_keys. The operator who revoked it had no way to know: the
// revocation was audited as successful, and nothing afterwards said it had been
// undone.
//
// The session is removed before the flow is driven, which is the same state
// `replaceSession` sees for a mid-flow revocation — the pointer the flow read is no
// longer the pointer stored — without depending on the timing of a real one.
func TestDeviceFlowWillNotActivateASessionThatIsGone(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.Grant)

	// The operator revokes it while the provider round-trip is in flight.
	env.broker.removeSession(env.session.ID)

	// A revocation now also cancels the flow's polling (#163), and a flow that
	// notices the cancellation stops before it has anything to withdraw. This test is
	// about the other ordering, which is still reachable and is the one that can leave
	// a credential behind: the revocation landed while this goroutine was inside the
	// token request, so it had already passed the select that watches for
	// cancellation and runs to completion regardless. Re-arming the channel after the
	// revocation is how that ordering is made deterministic — the flow has not
	// started, so nothing else can be reading it — and it leaves the pointer-identity
	// check at the end of the flow as the only thing standing between a revoked
	// session and an active one with a key installed.
	env.session.cancel = make(chan struct{})

	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("a session revoked during its device flow was brought back by the flow completing: %+v",
			session)
	}

	event := env.auditEvent(t, "authentication_denied")
	if event.ErrorCode != "SESSION_GONE" {
		t.Errorf("denial recorded with error_code %q, want SESSION_GONE", event.ErrorCode)
	}
	if event.Success {
		t.Error("the denial event is recorded with success=true")
	}
	for _, e := range env.auditEvents(t) {
		if e.EventType == "authentication_successful" {
			t.Fatal("completing the flow for a revoked session was recorded as a successful login (#217)")
		}
	}

	// The credential half, which is what makes this more than an accounting error.
	// The key was generated and installed before the store was attempted, so
	// refusing to activate without withdrawing it would leave a working SSH key for
	// a session that does not exist — reachable by anyone holding the private half,
	// and invisible to `oidc-admin list-sessions`.
	authorizedKeys := filepath.Join(env.homeDir, env.session.UserID, ".ssh", "authorized_keys")
	if data, err := os.ReadFile(authorizedKeys); err == nil && strings.Contains(string(data), "@oidc-pam-") {
		t.Errorf("the key issued to a revoked session is still authorized, so the revocation left a "+
			"usable login behind (#217):\n%s", data)
	}
	if _, err := env.broker.keyManager.LoadKey(env.session.ID); err == nil {
		t.Error("the key pair issued to a revoked session is still in the key store")
	}
}

// TestDeviceFlowDeniesAnUntrustedDeviceWhenPolicyRequiresIt is the enforcement half
// of require_device_trust (#212). The setting appears in every shipped provider
// template and used to write a metadata key that nothing read, so `production` tiers
// asking for a hardware-backed login admitted any device at all.
//
// It is enforced here, at the end of the flow, rather than during policy evaluation:
// device trust comes from the token's `amr` claim (RFC 8176 `hwk`/`fido`), and when
// policy is evaluated no token exists yet.
func TestDeviceFlowDeniesAnUntrustedDeviceWhenPolicyRequiresIt(t *testing.T) {
	env := newPollTestEnv(t)
	// What a matching policy with require_device_trust: true resolves to. The test
	// issuer's tokens carry no amr, which is what an IdP that was never configured to
	// send one does.
	env.session.RequireDeviceTrust = true
	env.idp.Script(testoidc.Grant)

	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("require_device_trust admitted an identity whose token has no hardware-backed amr "+
			"method: %+v", session)
	}

	event := env.auditEvent(t, "authentication_denied")
	if event.ErrorCode != "DEVICE_NOT_TRUSTED" {
		t.Errorf("denial recorded with error_code %q, want DEVICE_NOT_TRUSTED", event.ErrorCode)
	}
	for _, e := range env.auditEvents(t) {
		if e.EventType == "authentication_successful" {
			t.Fatal("a login denied for device trust was also recorded as successful")
		}
	}

	authorizedKeys := filepath.Join(env.homeDir, env.session.UserID, ".ssh", "authorized_keys")
	if data, err := os.ReadFile(authorizedKeys); err == nil && strings.Contains(string(data), "@oidc-pam-") {
		t.Errorf("a login denied for device trust installed a login key:\n%s", data)
	}
}

// TestDeviceFlowAdmitsATrustedDevice is the other half: the requirement must be
// satisfiable, or it is just an outage. The `amr` claim carrying `hwk` is what
// UserInfo.DeviceTrusted is derived from.
func TestDeviceFlowAdmitsATrustedDevice(t *testing.T) {
	env := newPollTestEnv(t)
	env.session.RequireDeviceTrust = true
	// RFC 8176 `hwk`: proof of possession of a hardware-secured key. `fido` is the
	// other method the broker accepts.
	claims := testoidc.DefaultClaims()
	claims["amr"] = []string{"pwd", "hwk"}
	env.idp.SetClaims(claims)
	env.idp.Script(testoidc.Grant)

	env.run(t)

	session := env.activeSession()
	if session == nil {
		t.Fatal("an identity presenting a hardware-key amr method was denied under require_device_trust")
	}
	if !session.IsActive {
		t.Error("the session is inactive after a login that satisfies require_device_trust")
	}
	if !session.DeviceTrusted {
		t.Error("the session does not record the device as trusted, though amr carried hwk")
	}
}

// refreshTestBroker builds a broker for the RefreshSession guards: a real policy
// engine over cfg, a token store, a file-backed audit logger and one session in the
// map.
//
// No provider is registered. Every guard under test has to answer before the
// provider is looked up, so a test that reaches the provider gets
// PROVIDER_NOT_FOUND rather than a false pass — which is itself the assertion that
// the guard ran too late.
func refreshTestBroker(t *testing.T, cfg *config.Config, session *Session) (*Broker, string) {
	t.Helper()

	// "sync" writes on the calling goroutine, so a denial is on disk by the time
	// RefreshSession returns and no Start()/Stop() pair is needed.
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

	broker := &Broker{
		config:       cfg,
		sessions:     make(map[string]*Session),
		policyEngine: newTestPolicyEngine(t, cfg),
		providers:    map[string]*OIDCProvider{},
		auditLogger:  auditLogger,
		tokenManager: newTestTokenManager(t),
	}
	broker.setSession(session)
	return broker, auditPath
}

// auditEventsAt reads the events an audit logger wrote to path. A run that recorded
// nothing yields nil rather than an error, so a test can assert on an absence.
func auditEventsAt(t *testing.T, path string) []security.AuditEvent {
	t.Helper()

	data, err := os.ReadFile(path) // #nosec G304 -- a path this test just created
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

func refreshTestConfig() *config.Config {
	return &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime:    time.Hour,
			RefreshThreshold: 15 * time.Minute,
		},
	}
}

// TestRefreshSessionRefusesAPendingSession is the acceptance gate for #215.
//
// A device-flow session is stored with IsActive: false and an ExpiresAt one token
// lifetime out, before anyone has approved anything. Every check RefreshSession made
// was satisfied by such a session: it existed, the user matched, it had not expired,
// and it was inside the refresh threshold only if the threshold was wide — so the
// "not close to expiry" branch returned createSuccessResponse, a `success: true`
// carrying the session ID and expiry for a login that nobody had authenticated.
//
// The severity is bounded by the wire: refresh_session requires a root peer over the
// IPC socket (internal/ipc verifyPeerCredentials) and internal/brokerclient has no
// RefreshSession, so no shipped client can reach it. It is a fail-open on a public
// broker operation, closed here rather than left to depend on those two facts
// continuing to hold.
func TestRefreshSessionRefusesAPendingSession(t *testing.T) {
	// Far enough out that the "not close to expiry" early return is the branch that
	// answers, which is the one that used to say success.
	session := &Session{
		ID:        "pending-device-flow",
		UserID:    "test-user",
		Provider:  "test-provider",
		IsActive:  false,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	broker, _ := refreshTestBroker(t, refreshTestConfig(), session)

	resp, err := broker.RefreshSession("pending-device-flow", "test-user")
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if resp.Success {
		t.Fatalf("refreshing a session nobody has authenticated returned success (%+v); the device "+
			"flow had not completed (#215)", resp)
	}
	if resp.ErrorCode != "SESSION_NOT_ACTIVE" {
		t.Errorf("error_code = %q, want SESSION_NOT_ACTIVE", resp.ErrorCode)
	}
}

// TestRefreshSessionRefusesAnExpiredSession covers the same fail-open from the other
// direction. An ExpiresAt in the past made time.Until negative, so the
// "close to expiry" comparison was false, the early return was skipped — and the
// session was renewed. Expiry therefore bounded nothing at all for a client that
// kept calling.
func TestRefreshSessionRefusesAnExpiredSession(t *testing.T) {
	session := &Session{
		ID:        "expired-session",
		UserID:    "test-user",
		Provider:  "test-provider",
		IsActive:  true,
		TokenID:   "some-token",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	broker, _ := refreshTestBroker(t, refreshTestConfig(), session)

	resp, err := broker.RefreshSession("expired-session", "test-user")
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if resp.Success {
		t.Fatalf("an expired session was refreshed back to life: %+v", resp)
	}
	if resp.ErrorCode != "SESSION_EXPIRED" {
		t.Errorf("error_code = %q, want SESSION_EXPIRED", resp.ErrorCode)
	}
	// Dropped, not merely refused: leaving it in the map keeps the SSH key
	// installed for the rest of its own window.
	if got := broker.getSession("expired-session"); got != nil {
		t.Error("the expired session is still in the session map after the refresh was refused")
	}
}

// TestRefreshSessionEnforcesMaxSessionDuration is the enforcement half of
// max_session_duration (#212). The setting parsed, loaded and was read by nothing:
// a session's life was `token_lifetime` from each refresh, without limit, so a
// policy naming a two-hour ceiling bounded a session that could run for weeks.
//
// The ceiling is measured from CreatedAt, so it is a ceiling on the session rather
// than on the gap between refreshes.
func TestRefreshSessionEnforcesMaxSessionDuration(t *testing.T) {
	session := &Session{
		ID:          "long-running-session",
		UserID:      "test-user",
		Provider:    "test-provider",
		IsActive:    true,
		TokenID:     "some-token",
		CreatedAt:   time.Now().Add(-3 * time.Hour),
		ExpiresAt:   time.Now().Add(30 * time.Minute), // not expired in its own right
		MaxDuration: 2 * time.Hour,
	}
	broker, _ := refreshTestBroker(t, refreshTestConfig(), session)

	resp, err := broker.RefreshSession("long-running-session", "test-user")
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if resp.Success {
		t.Fatalf("a session three hours into a two-hour max_session_duration was refreshed: %+v", resp)
	}
	if resp.ErrorCode != "SESSION_EXPIRED" {
		t.Errorf("error_code = %q, want SESSION_EXPIRED", resp.ErrorCode)
	}
	if got := broker.getSession("long-running-session"); got != nil {
		t.Error("the session is still in the map after reaching its maximum duration")
	}
}

// TestSessionExpiryIsCappedByMaxDuration covers the arithmetic directly, including
// the case that matters most: the last refresh before the ceiling must not push the
// expiry — and with it the SSH key's `expiry-time=` — past it.
func TestSessionExpiryIsCappedByMaxDuration(t *testing.T) {
	broker := &Broker{config: refreshTestConfig()} // TokenLifetime: 1h

	createdAt := time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name        string
		now         time.Time
		maxDuration time.Duration
		want        time.Time
	}{
		{
			name: "no ceiling gives a full token lifetime",
			now:  createdAt,
			want: createdAt.Add(time.Hour),
		},
		{
			name:        "a ceiling beyond the token lifetime does not extend it",
			now:         createdAt,
			maxDuration: 8 * time.Hour,
			want:        createdAt.Add(time.Hour),
		},
		{
			name:        "a ceiling inside the token lifetime caps it",
			now:         createdAt,
			maxDuration: 30 * time.Minute,
			want:        createdAt.Add(30 * time.Minute),
		},
		{
			// The refresh 90 minutes into a 2-hour session gets 30 minutes, not 60.
			name:        "the last refresh before the ceiling is trimmed to it",
			now:         createdAt.Add(90 * time.Minute),
			maxDuration: 2 * time.Hour,
			want:        createdAt.Add(2 * time.Hour),
		},
		{
			name:        "a zero ceiling means no ceiling",
			now:         createdAt.Add(90 * time.Minute),
			maxDuration: 0,
			want:        createdAt.Add(150 * time.Minute),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := broker.sessionExpiry(createdAt, tc.now, tc.maxDuration)
			if !got.Equal(tc.want) {
				t.Errorf("sessionExpiry(created=%v, now=%v, max=%v) = %v, want %v",
					createdAt, tc.now, tc.maxDuration, got, tc.want)
			}
		})
	}
}

// TestRefreshSessionRefusesWhatPolicyNoLongerAllows is the acceptance gate for the
// re-evaluation half of #215. Policy used to be evaluated exactly once, when a login
// started, so every control an operator can change afterwards — group membership, an
// ip_whitelist, a country list, a deny-on-risk policy — had no effect on a session
// already running. A client that kept refreshing kept the session, and the SSH key
// whose expiry-time= is derived from the same ExpiresAt, alive indefinitely; the only
// remedy was for an operator to find and revoke the session by hand.
//
// Here the operator has added a require_groups the live session's identity does not
// satisfy, which is the ordinary shape of "revoke this person's access".
func TestRefreshSessionRefusesWhatPolicyNoLongerAllows(t *testing.T) {
	cfg := refreshTestConfig()
	cfg.Authentication.Policies = map[string]config.AuthenticationPolicy{
		"default": {RequireGroups: []string{"production-access"}},
	}

	session := &Session{
		ID:        "tightened-out",
		UserID:    "test-user",
		Provider:  "test-provider",
		Groups:    []string{"researchers"}, // not production-access
		IsActive:  true,
		TokenID:   "some-token",
		CreatedAt: time.Now(),
		// Inside the refresh threshold, so a passing policy check would go on to
		// look for the provider — which this broker does not have, so a false pass
		// is distinguishable from a real one.
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	broker, auditPath := refreshTestBroker(t, cfg, session)

	resp, err := broker.RefreshSession("tightened-out", "test-user")
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if resp.Success {
		t.Fatalf("a session whose identity no longer satisfies require_groups was refreshed: %+v", resp)
	}
	if resp.ErrorCode != "POLICY_DENIED" {
		t.Errorf("error_code = %q, want POLICY_DENIED", resp.ErrorCode)
	}
	// The session is dropped rather than left live until its own expiry: policy says
	// this identity may not have this access, and the SSH key stays installed for as
	// long as the session does.
	if got := broker.getSession("tightened-out"); got != nil {
		t.Error("the session survived a policy denial, so its SSH key stays installed until it expires")
	}

	// An access that ends because policy changed is the event an operator is looking
	// for when they ask whether the change took effect, so it has to be in the trail
	// with the reason — not just refused to the caller.
	events := auditEventsAt(t, auditPath)
	var denial *security.AuditEvent
	for i := range events {
		if events[i].EventType == "session_refresh_denied" {
			denial = &events[i]
		}
	}
	if denial == nil {
		t.Fatalf("the refresh denial was not audited; the log holds %+v", events)
	}
	if denial.Success {
		t.Error("the denial is recorded with success=true")
	}
	if denial.ErrorCode != "POLICY_DENIED" {
		t.Errorf("audited error_code = %q, want POLICY_DENIED", denial.ErrorCode)
	}
	if !strings.Contains(denial.ErrorMessage, "production-access") {
		t.Errorf("audited reason %q does not name the group the identity is missing, so the record does "+
			"not say why the access ended", denial.ErrorMessage)
	}
}

// TestRefreshSessionAllowsWhatPolicyStillAllows is what stops the re-evaluation from
// being an outage. A session whose identity still satisfies the policy must refresh
// — and reaching PROVIDER_NOT_FOUND is the proof it got past every guard, since this
// broker registers no provider.
func TestRefreshSessionAllowsWhatPolicyStillAllows(t *testing.T) {
	cfg := refreshTestConfig()
	cfg.Authentication.Policies = map[string]config.AuthenticationPolicy{
		"default": {RequireGroups: []string{"production-access"}},
	}

	session := &Session{
		ID:        "still-allowed",
		UserID:    "test-user",
		Provider:  "test-provider",
		Groups:    []string{"researchers", "production-access"},
		IsActive:  true,
		TokenID:   "some-token",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	broker, _ := refreshTestBroker(t, cfg, session)

	resp, err := broker.RefreshSession("still-allowed", "test-user")
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if resp.ErrorCode == "POLICY_DENIED" {
		t.Fatalf("a session that still satisfies require_groups was denied by the re-evaluation: %+v", resp)
	}
	if resp.ErrorCode != "PROVIDER_NOT_FOUND" {
		t.Errorf("error_code = %q, want PROVIDER_NOT_FOUND: the refresh should have got past every "+
			"guard and on to the token exchange", resp.ErrorCode)
	}
	if got := broker.getSession("still-allowed"); got == nil {
		t.Error("a session that policy still allows was dropped")
	}
}

// TestCheckSessionDoesNotResurrectARevokedSession drives the compare-and-set in
// CheckSession from the outside, the other half of #217: once a session has been
// revoked, no check that was already in flight may put it back.
//
// Revocation is the invariant, not the interleaving — the assertion holds however
// the goroutines are scheduled, so the test cannot flake. Under -race it is also
// what shows that the clone, rather than an in-place write to a pointer other
// readers hold, is what CheckSession does.
func TestCheckSessionDoesNotResurrectARevokedSession(t *testing.T) {
	session := &Session{
		ID:           "checked-then-revoked",
		UserID:       "test-user",
		IsActive:     true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
		LastAccessed: time.Now().Add(-time.Minute),
	}
	broker, _ := refreshTestBroker(t, refreshTestConfig(), session)

	const checkers = 8
	var wg sync.WaitGroup
	for range checkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if _, err := broker.CheckSession(session.ID, session.UserID); err != nil {
					t.Errorf("CheckSession: %v", err)
					return
				}
			}
		}()
	}

	broker.removeSession(session.ID)
	wg.Wait()

	if got := broker.getSession(session.ID); got != nil {
		t.Errorf("a revoked session is back in the session map, put there by a check that was already "+
			"in flight (#217): %+v", got)
	}
}

// TestCheckSessionReportsTheAccessItJustRecorded covers the stale-pointer half of
// #215. CheckSession clones the session, writes the clone, and then built its
// response from the pointer it had read — so the caller was handed a LastAccessed
// from before this check, and would read whatever a future in-place mutation
// happened to leave there.
func TestCheckSessionReportsTheAccessItJustRecorded(t *testing.T) {
	before := time.Now().Add(-time.Hour)
	session := &Session{
		ID:           "checked",
		UserID:       "test-user",
		IsActive:     true,
		CreatedAt:    before,
		ExpiresAt:    time.Now().Add(time.Hour),
		LastAccessed: before,
	}
	broker, _ := refreshTestBroker(t, refreshTestConfig(), session)

	resp, err := broker.CheckSession("checked", "test-user")
	if err != nil {
		t.Fatalf("CheckSession: %v", err)
	}
	if !resp.Success {
		t.Fatalf("CheckSession refused a live session: %+v", resp)
	}

	// The stored session records this check...
	stored := broker.getSession("checked")
	if stored == nil {
		t.Fatal("the session is gone after a successful check")
	}
	if !stored.LastAccessed.After(before) {
		t.Errorf("stored LastAccessed = %v, not updated past %v", stored.LastAccessed, before)
	}
	// ...and the pointer that was read is left alone, which is what makes the
	// concurrent reader safe.
	if !session.LastAccessed.Equal(before) {
		t.Errorf("the session pointer held by other readers was mutated in place: LastAccessed = %v, "+
			"want the unchanged %v", session.LastAccessed, before)
	}
}

// TestReplaceSessionRequiresThePointerItWasGiven pins the primitive both fixes rest
// on. Every path that invalidates a session either deletes the entry or stores a
// fresh copy, so "the pointer I read is still the pointer stored" is exactly
// "nothing has happened to this session since I read it" — a condition that
// re-reading the session's fields cannot establish.
func TestReplaceSessionRequiresThePointerItWasGiven(t *testing.T) {
	broker := &Broker{sessions: make(map[string]*Session)}

	stored := &Session{ID: "s", UserID: "u", IsActive: true}
	broker.setSession(stored)
	if broker.getSession("s") != stored {
		t.Fatal("setSession did not store the session it was given")
	}

	updated := *stored
	updated.LastAccessed = time.Now()
	if !broker.replaceSession(stored, &updated) {
		t.Fatal("replaceSession refused a store against the pointer it was reading")
	}
	if broker.getSession("s") != &updated {
		t.Error("replaceSession reported success without storing the update")
	}

	// A second store against the now-stale pointer must be refused: something has
	// happened to the session since that pointer was read.
	stale := *stored
	if broker.replaceSession(stored, &stale) {
		t.Error("replaceSession accepted a store against a stale pointer, so a slow path could " +
			"overwrite a newer session with its own older copy")
	}

	// And a store against a deleted entry, which is the revocation case.
	broker.removeSession("s")
	if broker.replaceSession(&updated, &updated) {
		t.Error("replaceSession accepted a store for a session that had been removed, which is how a " +
			"revoked session came back (#217)")
	}
}
