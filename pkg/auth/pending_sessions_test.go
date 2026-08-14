package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
)

// These tests are about the logins the broker is holding that nobody has completed:
// a client asked to log in as some account, the broker started a device
// authorization on its behalf, and the user has not approved it. Until then the
// request has cost the host a session, a goroutine and a round trip to the identity
// provider, and has proved nothing whatsoever about who sent it — sshd runs its PAM
// stack for whatever username a remote client offers, before that client has
// authenticated at all.
//
// #163 is what happens when such a login is counted as though it had succeeded.
// Ten connection attempts naming one account filled that account's
// max_concurrent_sessions with authentications nobody had approved, and the real
// user was refused TOO_MANY_SESSIONS for as long as the device codes lived; a
// hundred of them across invented usernames filled a host-wide pool and refused
// every login on the machine. Both are driven through Authenticate here, because
// both were properties of how the counting and the storing were ordered rather than
// of any one helper.

// pendingEnv is a broker wired to a device-authorization endpoint that counts what
// it is asked for. The count is the point: a request the broker is going to refuse
// must not have spent an authenticated POST to the site's identity provider first.
type pendingEnv struct {
	broker *Broker
	server *httptest.Server
	// deviceRequests counts device-authorization requests the provider received.
	deviceRequests atomic.Int64
	// expiresIn is what the endpoint reports as the device code's lifetime, so a test
	// can play a provider that hands out very long-lived codes.
	expiresIn atomic.Int64
	auditPath string
}

func newPendingEnv(t *testing.T) *pendingEnv {
	t.Helper()

	env := &pendingEnv{}
	env.expiresIn.Store(600)

	var issued atomic.Int64
	env.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := issued.Add(1)
		env.deviceRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DeviceAuthResponse{
			// A distinct code per flow, so a test that asserts on which session was
			// displaced is not looking at two flows that are indistinguishable.
			DeviceCode:      fmt.Sprintf("device-code-%d", n),
			UserCode:        fmt.Sprintf("CODE-%d", n),
			VerificationURI: "https://example.com/verify",
			ExpiresIn:       int(env.expiresIn.Load()),
			Interval:        5,
		})
	}))
	t.Cleanup(env.server.Close)

	provider := &OIDCProvider{
		Name: "test-provider",
		Config: config.OIDCProvider{
			Name:            "test-provider",
			Issuer:          env.server.URL,
			ClientID:        "test-client",
			Scopes:          []string{"openid", "profile"},
			DeviceEndpoint:  env.server.URL + "/device",
			EnabledForLogin: true,
		},
		httpClient: env.server.Client(),
	}

	// A real, file-backed logger: what the broker records about a login it refused or
	// abandoned is part of what these tests are checking. "sync" writes on the calling
	// goroutine, so nothing is left buffered.
	env.auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := security.NewAuditLogger(config.AuditConfig{
		Enabled:          true,
		Outputs:          []config.AuditOutput{{Type: "file", Path: env.auditPath}},
		OverflowStrategy: "sync",
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = auditLogger.Stop() })

	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime:    time.Hour,
			RefreshThreshold: 15 * time.Minute,
		},
	}

	env.broker = &Broker{
		config:       cfg,
		sessions:     make(map[string]*Session),
		policyEngine: &PolicyEngine{config: cfg},
		providers:    map[string]*OIDCProvider{"test-provider": provider},
		auditLogger:  auditLogger,
		stopChan:     make(chan struct{}),
		// No poll ever fires: these tests are about what happens to a login *before*
		// anyone approves it, and the token endpoint is not what is being played here.
		// The unit multiplies the provider's interval, so an hour puts the first poll
		// five hours out — the cancellation and deadline branches of the loop are
		// reached without it.
		pollIntervalUnit: time.Hour,
		// A fixed passwd table, so the local-account gate behaves the same wherever the
		// suite runs.
		lookupLocalUID: testLookupUID,
	}
	// Registered after server.Close, so it runs before it: the polling goroutines are
	// released while the endpoint they talk to is still up.
	t.Cleanup(func() {
		close(env.broker.stopChan)
		env.broker.wg.Wait()
	})

	return env
}

// authenticate asks for a login as userID from sourceIP.
func (e *pendingEnv) authenticate(t *testing.T, userID, sourceIP string) *AuthResponse {
	t.Helper()

	resp, err := e.broker.Authenticate(&AuthRequest{
		UserID:     userID,
		SourceIP:   sourceIP,
		TargetHost: "test-host",
		LoginType:  "ssh",
	})
	if err != nil {
		t.Fatalf("Authenticate(%q from %q): %v", userID, sourceIP, err)
	}
	return resp
}

// countPending returns how many unfinished logins the broker holds for one
// (account, source) pair.
func (e *pendingEnv) countPending(userID, sourceIP string) int {
	e.broker.sessionMutex.RLock()
	defer e.broker.sessionMutex.RUnlock()

	count := 0
	for _, session := range e.broker.sessions {
		if !session.IsActive && session.UserID == userID && session.SourceIP == sourceIP {
			count++
		}
	}
	return count
}

// pendingSessionFixture is a session for a login that has started a device flow and
// not completed one: what Authenticate stores between handing a user code to a
// client and that client's user approving it. Built directly rather than through
// Authenticate where a test needs a hundred of them, or needs to move one back in
// time without racing the goroutine that would be polling for it.
func pendingSessionFixture(id, userID, sourceIP string) *Session {
	now := time.Now()
	return &Session{
		ID:           id,
		UserID:       userID,
		SourceIP:     sourceIP,
		Provider:     "test-provider",
		LoginType:    "ssh",
		IsActive:     false,
		CreatedAt:    now,
		ExpiresAt:    now.Add(defaultPendingAuthLifetime),
		LastAccessed: now,
		cancel:       make(chan struct{}),
	}
}

// agePendingSession moves a stored pending session back in time by d, replacing the
// map entry rather than mutating it in place — the store's own convention, and the
// only safe thing to do to a session something else may be reading.
func agePendingSession(t *testing.T, broker *Broker, sessionID string, d time.Duration) {
	t.Helper()

	broker.sessionMutex.Lock()
	defer broker.sessionMutex.Unlock()

	stored, ok := broker.sessions[sessionID]
	if !ok {
		t.Fatalf("no session %q to age", sessionID)
	}
	aged := *stored
	aged.CreatedAt = stored.CreatedAt.Add(-d)
	aged.ExpiresAt = stored.ExpiresAt.Add(-d)
	aged.LastAccessed = stored.LastAccessed.Add(-d)
	broker.sessions[sessionID] = &aged
}

// isClosed reports whether a pending session's cancel channel has been closed,
// which is how the goroutine polling for it is told to stop.
func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// TestAbandonedPendingFlowsDoNotDenyTheAccountItsLogin is the regression gate for
// #163, and fails on the code before it in two places at once.
//
// A client that has authenticated nothing repeatedly asks to log in as someone
// else's account. Every one of those requests is abandoned — no user ever visits the
// verification URL, which is the whole attack: it costs the sender nothing.
//
// Before the fix, each abandoned request took a slot in the victim's
// max_concurrent_sessions and held it for the device code's lifetime, so the fourth
// request against a limit of three locked the account out and the victim's own login
// was refused TOO_MANY_SESSIONS. After it, unfinished logins are counted separately,
// against the (account, source address) pair that asked for them — the address being
// the part of the request a remote client does not choose — so the flood exhausts the
// attacker's own budget and the victim, arriving from a different address, is served.
func TestAbandonedPendingFlowsDoNotDenyTheAccountItsLogin(t *testing.T) {
	env := newPendingEnv(t)

	// The limit an operator sets on how many sessions one person may hold at once.
	env.broker.config.Authentication.MaxConcurrentSessions = 3

	const (
		victim     = "alice"
		attackerIP = "198.51.100.4"
		victimIP   = "203.0.113.9"
	)

	admitted, refused := 0, 0
	for i := 0; i < 10; i++ {
		resp := env.authenticate(t, victim, attackerIP)
		switch {
		case resp.Success:
			admitted++
		case resp.ErrorCode == "TOO_MANY_PENDING_AUTHS":
			refused++
		default:
			t.Fatalf("attempt %d was refused %q (%s), want either a device code or the "+
				"pending-flow cap; a flood of unfinished logins must not be answered with a "+
				"limit that belongs to the account (#163)", i+1, resp.ErrorCode, resp.ErrorMessage)
		}
	}

	if admitted != defaultMaxPendingAuthsPerSource {
		t.Errorf("%d of 10 abandoned logins were admitted, want %d: one account and address may "+
			"have max_pending_auths_per_source unfinished logins in flight and no more",
			admitted, defaultMaxPendingAuthsPerSource)
	}
	if refused != 10-defaultMaxPendingAuthsPerSource {
		t.Errorf("%d attempts were refused with TOO_MANY_PENDING_AUTHS, want %d",
			refused, 10-defaultMaxPendingAuthsPerSource)
	}
	if held := env.countPending(victim, attackerIP); held != defaultMaxPendingAuthsPerSource {
		t.Errorf("the broker holds %d unfinished logins for that pair, want %d", held,
			defaultMaxPendingAuthsPerSource)
	}
	// The refused attempts must not have reached the identity provider: a cap that is
	// applied after the round trip still lets an unauthenticated client spend the
	// site's device-authorization quota.
	if got := env.deviceRequests.Load(); got != int64(defaultMaxPendingAuthsPerSource) {
		t.Errorf("the provider's device endpoint saw %d requests, want %d — one per admitted "+
			"login and none for a refused one", got, defaultMaxPendingAuthsPerSource)
	}

	// The account is not locked out. This is the assertion the issue is about.
	resp := env.authenticate(t, victim, victimIP)
	if !resp.Success {
		t.Fatalf("the account's own login was refused %q (%s) while %d abandoned "+
			"authentications for it were in flight from elsewhere: unfinished logins nobody "+
			"approved must not consume the account's session limit (#163)",
			resp.ErrorCode, resp.ErrorMessage, defaultMaxPendingAuthsPerSource)
	}
	if !resp.RequiresDevice || resp.DeviceCode == "" {
		t.Errorf("the login was admitted without a device code to complete it: %+v", resp)
	}
}

// A slot held by a login nobody completed has to come back on its own. A cap whose
// entries live forever is not a fix, it is the same denial of service with a
// different message — and before this the entry's lifetime was the device code's
// expires_in, a number the provider chooses and may set as high as 24 hours.
func TestPendingLoginSlotIsReleasedWhenItsWindowCloses(t *testing.T) {
	env := newPendingEnv(t)

	const (
		user     = "alice"
		sourceIP = "198.51.100.4"
	)

	for i := 0; i < defaultMaxPendingAuthsPerSource; i++ {
		env.broker.setSession(pendingSessionFixture(fmt.Sprintf("pending-%d", i), user, sourceIP))
	}

	if resp := env.authenticate(t, user, sourceIP); resp.ErrorCode != "TOO_MANY_PENDING_AUTHS" {
		t.Fatalf("a login at the pending cap answered %q, want TOO_MANY_PENDING_AUTHS", resp.ErrorCode)
	}

	// Time passes, on the broker's clock rather than the test's: every one of those
	// unfinished logins is now past the window it was allowed.
	for i := 0; i < defaultMaxPendingAuthsPerSource; i++ {
		agePendingSession(t, env.broker, fmt.Sprintf("pending-%d", i), defaultPendingAuthLifetime+time.Minute)
	}

	if resp := env.authenticate(t, user, sourceIP); !resp.Success {
		t.Fatalf("a login was refused %q (%s) while every unfinished login counted against it "+
			"was past its own deadline; the entries have to stop counting when their window "+
			"closes, not when the sweep next runs (#163)", resp.ErrorCode, resp.ErrorMessage)
	}

	// And the sweep collects them, closing each one's cancel channel so the goroutine
	// that was polling for it stops too.
	swept := env.broker.getSession("pending-0")
	if swept == nil {
		t.Fatal("the aged pending session is already gone; nothing left to observe the sweep on")
	}
	env.broker.expireSessions(time.Now())
	if env.broker.getSession("pending-0") != nil {
		t.Error("the sweep left a pending session that is past its deadline in the store")
	}
	if !isClosed(swept.cancel) {
		t.Error("the swept pending session's poll loop was not told to stop, so it keeps a device " +
			"code warm for a login the broker has forgotten (#163)")
	}
}

// The window an unfinished login may hold its slot for is the broker's, not the
// provider's. A provider that hands out 24-hour device codes — the upper bound
// StartDeviceFlow accepts — used to set how long a pending session and its polling
// goroutine lived, which is how a handful of abandoned requests could occupy the
// host for a day.
func TestPendingLifetimeIsBoundedByTheBrokerNotTheProvider(t *testing.T) {
	env := newPendingEnv(t)
	env.expiresIn.Store(86400) // the most StartDeviceFlow will accept

	before := time.Now()
	resp := env.authenticate(t, "alice", "198.51.100.4")
	if !resp.Success {
		t.Fatalf("Authenticate refused the login: %q (%s)", resp.ErrorCode, resp.ErrorMessage)
	}

	session := env.broker.getSession(resp.SessionID)
	if session == nil {
		t.Fatal("the admitted login left no pending session")
	}

	limit := before.Add(defaultPendingAuthLifetime + time.Minute)
	if session.ExpiresAt.After(limit) {
		t.Errorf("the pending session expires at %s, about %s from now: a provider's expires_in "+
			"must not set how long an unfinished login holds its slot (#163)",
			session.ExpiresAt, session.ExpiresAt.Sub(before).Round(time.Second))
	}
	// And the client is told the earlier of the two deadlines, since the code stops
	// working when the broker stops polling for it.
	if resp.ExpiresAt.After(limit) {
		t.Errorf("the client was promised the code would work until %s, past the window the "+
			"broker will honour", resp.ExpiresAt)
	}
}

// The host-wide pool is the other half of #163: a client filling it with unfinished
// logins under invented usernames used to make every login on the machine answer
// RATE_LIMITED. A full pool now displaces a pending flow from whichever (account,
// source) pair holds the most, so holding the largest share is what makes you the
// one who pays for it, and a login from a pair holding nothing is still served.
func TestFullPendingPoolDisplacesItsLargestHolder(t *testing.T) {
	env := newPendingEnv(t)
	// A hoarder needs room to hoard; the per-source cap is what bounds it in the
	// default configuration.
	env.broker.config.Authentication.MaxPendingAuthsPerSource = hardMaxPendingAuthsPerSource

	const (
		hogUser = "bob"
		hogIP   = "198.51.100.4"
		hogHeld = 30
	)

	hogSessions := make([]*Session, 0, hogHeld)
	for i := 0; i < hogHeld; i++ {
		session := pendingSessionFixture(fmt.Sprintf("hog-%d", i), hogUser, hogIP)
		// Distinct creation times, so "the oldest of them" is a defined thing.
		session.CreatedAt = session.CreatedAt.Add(time.Duration(i) * time.Second)
		hogSessions = append(hogSessions, session)
		env.broker.setSession(session)
	}
	for i := 0; i < maxPendingAuthsOnHost-hogHeld; i++ {
		env.broker.setSession(pendingSessionFixture(
			fmt.Sprintf("single-%d", i), fmt.Sprintf("user-%d", i), "203.0.113.9"))
	}

	// A login from a pair holding nothing. The pool is full, and it is served anyway.
	resp := env.authenticate(t, "alice", "192.0.2.10")
	if !resp.Success {
		t.Fatalf("a login from an address holding no unfinished authentications was refused %q "+
			"(%s) because the host's pending pool was full of somebody else's: a full pool must "+
			"not be a host-wide lockout (#163)", resp.ErrorCode, resp.ErrorMessage)
	}

	// It was paid for by the largest holder's oldest flow, and that flow's poll loop
	// was told to stop — otherwise the pool's bound on goroutines and provider traffic
	// means nothing.
	displaced := hogSessions[0]
	if env.broker.getSession(displaced.ID) != nil {
		t.Errorf("session %q is still stored; the pool admitted a login without displacing the "+
			"oldest flow of its largest holder", displaced.ID)
	}
	if !isClosed(displaced.cancel) {
		t.Error("the displaced flow's poll loop was not told to stop, so its goroutine keeps " +
			"polling the provider for a session that no longer exists (#163)")
	}
	if held := env.countPending(hogUser, hogIP); held != hogHeld-1 {
		t.Errorf("the largest holder still has %d unfinished logins, want %d", held, hogHeld-1)
	}

	// The largest holder itself is the one that gets refused, and only once nobody
	// holds more than it does.
	requests := env.deviceRequests.Load()
	hogResp := env.authenticate(t, hogUser, hogIP)
	if hogResp.Success {
		t.Fatalf("the pair holding the largest share of a full pool was admitted again: %+v", hogResp)
	}
	if hogResp.ErrorCode != "RATE_LIMITED" {
		t.Errorf("error_code = %q, want RATE_LIMITED", hogResp.ErrorCode)
	}
	if got := env.deviceRequests.Load(); got != requests {
		t.Errorf("the refused login still made %d device-authorization request(s); admission has "+
			"to be decided before the provider is asked", got-requests)
	}
}

// max_concurrent_sessions is a bound on the access one identity holds at once, so
// what belongs in it is access that was granted. Established sessions count; logins
// still waiting for someone to approve them do not.
func TestPendingLoginsDoNotCountTowardsTheSessionLimit(t *testing.T) {
	env := newPendingEnv(t)
	env.broker.config.Authentication.MaxConcurrentSessions = 2

	const user = "alice"
	for i := 0; i < 2; i++ {
		env.broker.setSession(pendingSessionFixture(fmt.Sprintf("pending-%d", i), user, "198.51.100.4"))
	}
	if resp := env.authenticate(t, user, "203.0.113.9"); !resp.Success {
		t.Fatalf("a login was refused %q (%s) with two *unapproved* authentications for the "+
			"account in flight (#163)", resp.ErrorCode, resp.ErrorMessage)
	}

	// The same two, completed, do refuse it.
	for i := 0; i < 2; i++ {
		established := pendingSessionFixture(fmt.Sprintf("active-%d", i), user, "198.51.100.4")
		established.IsActive = true
		established.ExpiresAt = time.Now().Add(time.Hour)
		established.cancel = nil
		env.broker.setSession(established)
	}
	resp := env.authenticate(t, user, "203.0.113.9")
	if resp.ErrorCode != "TOO_MANY_SESSIONS" {
		t.Errorf("a login with the account's session limit already granted answered %q, want "+
			"TOO_MANY_SESSIONS: the limit still has to be enforced against sessions that exist",
			resp.ErrorCode)
	}
}

// A login for an account this host does not have could never have succeeded — sshd
// needs a passwd entry once the stack returns, and the identity binding resolves the
// account again when the flow completes — but it used to be found out only after the
// broker had spent an authenticated request to the site's identity provider and
// taken a slot in the pending pool. Every ssh scanner on the internet could do that.
func TestLoginForAnUnknownLocalAccountNeverReachesTheProvider(t *testing.T) {
	env := newPendingEnv(t)
	env.broker.config.Authentication.RequireLocalAccount = true

	resp := env.authenticate(t, "no-such-user", "198.51.100.4")
	if resp.Success {
		t.Fatalf("a login for an account this host does not have was admitted: %+v", resp)
	}
	if resp.ErrorCode != "NO_LOCAL_ACCOUNT" {
		t.Errorf("error_code = %q, want NO_LOCAL_ACCOUNT", resp.ErrorCode)
	}
	if got := env.deviceRequests.Load(); got != 0 {
		t.Errorf("the provider's device endpoint saw %d request(s) for an account that does not "+
			"exist here; an unauthenticated client must not be able to spend the site's "+
			"device-authorization quota on invented usernames (#163)", got)
	}
	if got := env.countPending("no-such-user", "198.51.100.4"); got != 0 {
		t.Errorf("the refused login left %d pending session(s) behind", got)
	}

	// An account that does exist is unaffected.
	if resp := env.authenticate(t, "alice", "198.51.100.4"); !resp.Success {
		t.Fatalf("the local-account gate refused a login for an account that exists: %q (%s)",
			resp.ErrorCode, resp.ErrorMessage)
	}
}

// Both bounds on an unfinished login are clamped at both ends. A configured value
// that is honoured however large it is fails open — the same shape as the unbounded
// int the IPC limiter narrowed to int32, where a very large configured cap became no
// cap at all — and zero has to mean "the default", not "no limit", because these
// settings are what stops an unauthenticated client consuming somebody else's
// capacity.
func TestPendingBoundsAreClampedAtBothEnds(t *testing.T) {
	for _, tc := range []struct {
		configured, want int
	}{
		{configured: 0, want: defaultMaxPendingAuthsPerSource},
		{configured: -1, want: defaultMaxPendingAuthsPerSource},
		{configured: 1, want: 1},
		{configured: hardMaxPendingAuthsPerSource, want: hardMaxPendingAuthsPerSource},
		{configured: hardMaxPendingAuthsPerSource + 1, want: hardMaxPendingAuthsPerSource},
		{configured: 1 << 30, want: hardMaxPendingAuthsPerSource},
	} {
		broker := &Broker{config: &config.Config{
			Authentication: config.AuthenticationConfig{MaxPendingAuthsPerSource: tc.configured},
		}}
		if got := broker.maxPendingAuthsPerSource(); got != tc.want {
			t.Errorf("max_pending_auths_per_source: %d became %d, want %d", tc.configured, got, tc.want)
		}
	}

	for _, tc := range []struct {
		configured, want time.Duration
	}{
		{configured: 0, want: defaultPendingAuthLifetime},
		{configured: -time.Hour, want: defaultPendingAuthLifetime},
		{configured: time.Second, want: minPendingAuthLifetime},
		{configured: 5 * time.Minute, want: 5 * time.Minute},
		{configured: hardMaxPendingAuthLifetime, want: hardMaxPendingAuthLifetime},
		{configured: 24 * time.Hour, want: hardMaxPendingAuthLifetime},
	} {
		broker := &Broker{config: &config.Config{
			Authentication: config.AuthenticationConfig{PendingAuthLifetime: tc.configured},
		}}
		if got := broker.pendingAuthLifetime(); got != tc.want {
			t.Errorf("pending_auth_lifetime: %s became %s, want %s", tc.configured, got, tc.want)
		}
	}
}

// Removing a pending session has to stop the goroutine polling for it. Before this
// the two had independent lifetimes: a revoked, swept or displaced login left a
// goroutine holding a live device code and polling the provider for it until that
// code's own expiry, so a bound on how many unfinished logins the host holds bounded
// nothing that those logins actually cost.
func TestRevokingAPendingLoginStopsItsPolling(t *testing.T) {
	env := newPendingEnv(t)

	resp := env.authenticate(t, "alice", "198.51.100.4")
	if !resp.Success {
		t.Fatalf("Authenticate refused the login: %q (%s)", resp.ErrorCode, resp.ErrorMessage)
	}

	env.broker.removeSession(resp.SessionID)

	// The wait is a guard, not a delay: a poll loop that honours the cancellation is
	// already gone by the time this runs, and one that does not would sit here until
	// the device code expired ten minutes later.
	done := make(chan struct{})
	go func() {
		defer close(done)
		env.broker.wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the goroutine polling for a session that was removed is still running; a " +
			"pending login and the work it costs have to end together (#163)")
	}

	// The user was waiting on that login and will be refused, so it is recorded —
	// with the code the completion path uses for the same condition (#217, #218).
	var abandoned *security.AuditEvent
	for _, event := range auditEventsAt(t, env.auditPath) {
		if event.EventType == "authentication_denied" && event.ErrorCode == "SESSION_GONE" {
			e := event
			abandoned = &e
		}
	}
	if abandoned == nil {
		t.Fatal("abandoning a revoked login's device authorization left no record; an operator " +
			"who revokes a session mid-flow has nothing saying what it interrupted (#218)")
	}
	if abandoned.SessionID != resp.SessionID {
		t.Errorf("the record names session %q, want the one that was revoked (%q)",
			abandoned.SessionID, resp.SessionID)
	}
}
