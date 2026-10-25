package auth

import (
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/internal/testoidc"
)

// A failed login stays queryable for a grace period, and one poll after the
// failure gets the failure (#179, broker conformance item 5). Every way the flow
// can fail is in here, because the way this goes wrong is one exit path that still
// deletes the session: its client then reads SESSION_NOT_FOUND, which looks
// exactly like a broker restart.
func TestAFailedLoginReportsWhyItFailed(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(env *pollTestEnv)
		wantCode string
	}{
		{
			name:     "declined at the provider",
			setup:    func(env *pollTestEnv) { env.idp.Script(testoidc.Pending, testoidc.AccessDenied) },
			wantCode: "ACCESS_DENIED",
		},
		{
			name:     "the provider says the code expired",
			setup:    func(env *pollTestEnv) { env.idp.Script(testoidc.Pending, testoidc.ExpiredToken) },
			wantCode: "SESSION_EXPIRED",
		},
		{
			name: "the code ran out of time with nobody signing in",
			setup: func(env *pollTestEnv) {
				env.idp.Script(testoidc.Pending)
				env.flow.ExpiresAt = time.Now().Add(5 * testPollUnit)
			},
			wantCode: "SESSION_EXPIRED",
		},
		{
			name: "signed in as somebody else",
			setup: func(env *pollTestEnv) {
				env.idp.SetClaims(map[string]any{
					"sub":                "sub-someone-else",
					"preferred_username": "someone-else",
					"email":              "someone-else@example.org",
					"groups":             []string{"researchers"},
				})
				env.idp.Script(testoidc.Grant)
			},
			wantCode: "IDENTITY_MISMATCH",
		},
		{
			name: "short of a required group",
			setup: func(env *pollTestEnv) {
				env.requiredGroups = []string{"hpc-admins"}
				env.idp.Script(testoidc.Grant)
			},
			wantCode: "GROUP_DENIED",
		},
		{
			name: "a policy wanted a trusted device",
			setup: func(env *pollTestEnv) {
				env.session.RequireDeviceTrust = true
				env.idp.Script(testoidc.Grant)
			},
			wantCode: "DEVICE_NOT_TRUSTED",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newPollTestEnv(t)
			tt.setup(env)

			env.run(t)

			resp, err := env.broker.CheckSession(env.session.ID, env.session.UserID)
			if err != nil {
				t.Fatalf("CheckSession: %v", err)
			}
			if resp.Success || resp.RequiresDevice {
				t.Fatalf("a failed login polled as success=%v requires_device=%v", resp.Success, resp.RequiresDevice)
			}
			if resp.ErrorCode != tt.wantCode {
				t.Errorf("error_code = %q, want %q — the poll after a failure must carry the failure",
					resp.ErrorCode, tt.wantCode)
			}
			if resp.ErrorMessage == "" {
				t.Error("the outcome has no message")
			}
			if resp.SessionID != env.session.ID {
				t.Errorf("session_id = %q, want %q", resp.SessionID, env.session.ID)
			}
		})
	}
}

// The record is not a session. It must not be refreshable, must carry nothing
// that could be mistaken for a credential, and must not be reported as a login in
// progress.
func TestTheRecordOfAFailedLoginIsNotASession(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.AccessDenied)
	env.run(t)

	ended := env.broker.getSession(env.session.ID)
	if ended == nil || !ended.isEnded() {
		t.Fatalf("the failed login left no record: %+v", ended)
	}
	if ended.IsActive || ended.TokenID != "" || ended.SSHKeyID != "" || ended.Email != "" || ended.cancel != nil {
		t.Errorf("the record carries more than who and where: %+v", ended)
	}

	resp, err := env.broker.RefreshSession(env.session.ID, env.session.UserID)
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if resp.Success || resp.ErrorCode != "SESSION_NOT_ACTIVE" {
		t.Errorf("refresh of a failed login = success %v, %q; want SESSION_NOT_ACTIVE", resp.Success, resp.ErrorCode)
	}

	if status := env.broker.Status(); status.PendingSessions != 0 || status.ActiveSessions != 0 {
		t.Errorf("status counts the failed login: %d active, %d pending", status.ActiveSessions, status.PendingSessions)
	}
	if infos := env.broker.ListSessions(); len(infos) != 1 || infos[0].Status != SessionStatusEnded {
		t.Errorf("listing = %+v, want the one record as %q", infos, SessionStatusEnded)
	}
}

// Why somebody's login failed is theirs to know. Another caller polling the same
// session ID gets FORBIDDEN, as for a live session, not the outcome.
func TestAFailedLoginsOutcomeIsOnlyForItsOwner(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.AccessDenied)
	env.run(t)

	resp, err := env.broker.CheckSession(env.session.ID, "mallory")
	if err != nil {
		t.Fatalf("CheckSession: %v", err)
	}
	if resp.ErrorCode != "FORBIDDEN" {
		t.Errorf("another caller got error_code %q, want FORBIDDEN", resp.ErrorCode)
	}
}

// After the grace period the record is gone for every lookup, whether or not the
// sweep has run: SESSION_NOT_FOUND is the right answer from then on. And the sweep
// does remove it, so failures do not accumulate.
func TestAFailedLoginIsForgottenAfterTheGracePeriod(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.AccessDenied)
	env.run(t)

	// Age the record past its grace period without waiting two minutes.
	ended := env.broker.getSession(env.session.ID)
	if ended == nil {
		t.Fatal("the failed login left no record")
	}
	aged := *ended
	aged.ExpiresAt = time.Now().Add(-time.Second)
	if !env.broker.replaceSession(ended, &aged) {
		t.Fatal("could not age the record")
	}

	resp, err := env.broker.CheckSession(env.session.ID, env.session.UserID)
	if err != nil {
		t.Fatalf("CheckSession: %v", err)
	}
	if resp.ErrorCode != "SESSION_NOT_FOUND" {
		t.Errorf("past the grace period error_code = %q, want SESSION_NOT_FOUND", resp.ErrorCode)
	}

	env.broker.expireSessions(time.Now())
	env.broker.sessionMutex.RLock()
	_, stillThere := env.broker.sessions[env.session.ID]
	env.broker.sessionMutex.RUnlock()
	if stillThere {
		t.Error("the sweep left an expired record in the map")
	}
}

// A failed login gives its slot in the pending pool back at once. If the record
// counted, a client could hold the per-source cap with logins it failed on
// purpose, and keep this account locked out for the length of the grace period.
func TestAFailedLoginDoesNotHoldAPendingSlot(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.Script(testoidc.AccessDenied)
	env.run(t)

	for i := 0; i < env.broker.maxPendingAuthsPerSource(); i++ {
		next := &Session{
			ID:        "after-" + string(rune('a'+i)),
			UserID:    env.session.UserID,
			SourceIP:  env.session.SourceIP,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Minute),
		}
		if admission := env.broker.admitPendingSession(next, time.Now()); !admission.admitted {
			t.Fatalf("login %d after the failure was refused with %s; the failed login is "+
				"still holding a slot", i+1, admission.errorCode)
		}
	}
}

// A login revoked while its flow ran is already gone, and failing afterwards does
// not put a record of the failure in its place. endSession is conditional on the
// session being the one the flow started with, like every late write (#217).
func TestEndingALoginThatWasRevokedLeavesNothingBehind(t *testing.T) {
	env := newPollTestEnv(t)
	env.broker.removeSession(env.session.ID)

	env.broker.endSession(env.session, outcomeAccessDenied)

	if got := env.broker.getSession(env.session.ID); got != nil {
		t.Errorf("ending a revoked login stored %+v", got)
	}
}
