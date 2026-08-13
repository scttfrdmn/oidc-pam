package auth

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
	sshpkg "github.com/scttfrdmn/oidc-pam/pkg/ssh"
)

func newAdminTestBroker(t *testing.T) *Broker {
	t.Helper()

	return &Broker{
		config: &config.Config{
			OIDC: config.OIDCConfig{
				Providers: []config.OIDCProvider{
					{Name: "okta"},
					{Name: "azure"},
				},
			},
			Authentication: config.AuthenticationConfig{TokenLifetime: time.Hour},
		},
		sessions: make(map[string]*Session),
	}
}

func TestStatusReportsVersionUptimeAndProviders(t *testing.T) {
	broker := newAdminTestBroker(t)

	// Before Start: no uptime is claimed. A broker that has been constructed but
	// is not serving should not report an uptime as if it were.
	status := broker.Status()
	if status.Version != "unknown" {
		t.Errorf("version = %q, want %q when unset", status.Version, "unknown")
	}
	if !status.StartedAt.IsZero() || status.Uptime != 0 {
		t.Errorf("unstarted broker reports started_at=%v uptime=%v, want zero", status.StartedAt, status.Uptime)
	}

	broker.SetVersion("v0.4.2")
	broker.startedAt = time.Now().Add(-90 * time.Minute)

	status = broker.Status()
	if status.Version != "v0.4.2" {
		t.Errorf("version = %q, want v0.4.2", status.Version)
	}
	if status.Uptime < 89*time.Minute || status.Uptime > 91*time.Minute {
		t.Errorf("uptime = %v, want ~90m", status.Uptime)
	}
	// Sorted, so the output does not reshuffle between two runs.
	if got := strings.Join(status.Providers, ","); got != "azure,okta" {
		t.Errorf("providers = %q, want \"azure,okta\"", got)
	}
}

func TestStatusCountsActiveAndPendingSessionsSeparately(t *testing.T) {
	broker := newAdminTestBroker(t)

	broker.setSession(&Session{ID: "a", UserID: "alice", IsActive: true})
	broker.setSession(&Session{ID: "b", UserID: "bob", IsActive: true})
	// A device flow the user has not completed. Counting it as active would
	// overstate how many people are logged in.
	broker.setSession(&Session{ID: "c", UserID: "carol", IsActive: false})

	status := broker.Status()
	if status.ActiveSessions != 2 {
		t.Errorf("active = %d, want 2", status.ActiveSessions)
	}
	if status.PendingSessions != 1 {
		t.Errorf("pending = %d, want 1", status.PendingSessions)
	}
}

func TestListSessionsLabelsStatusAndOrdersNewestFirst(t *testing.T) {
	broker := newAdminTestBroker(t)
	now := time.Now()

	broker.setSession(&Session{
		ID: "oldest", UserID: "alice", Provider: "okta", LoginType: "ssh",
		IsActive: true, CreatedAt: now.Add(-3 * time.Hour), ExpiresAt: now.Add(time.Hour),
	})
	broker.setSession(&Session{
		ID: "middle", UserID: "bob", Provider: "azure", LoginType: "console",
		IsActive: true, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Minute),
	})
	broker.setSession(&Session{
		ID: "newest", UserID: "carol", Provider: "okta", LoginType: "gui",
		IsActive: false, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	})

	sessions := broker.ListSessions()
	if len(sessions) != 3 {
		t.Fatalf("got %d sessions, want 3", len(sessions))
	}

	wantOrder := []string{"newest", "middle", "oldest"}
	for i, want := range wantOrder {
		if sessions[i].ID != want {
			t.Errorf("sessions[%d].ID = %q, want %q (order should be newest first)", i, sessions[i].ID, want)
		}
	}

	wantStatus := map[string]string{
		"oldest": SessionStatusActive,
		// Past its ExpiresAt but not yet swept: it is not usable, and reporting
		// it as active would be a lie.
		"middle": SessionStatusExpired,
		// Authenticated flag not set: the user has not finished the device flow.
		"newest": SessionStatusPending,
	}
	for _, session := range sessions {
		if got := session.Status; got != wantStatus[session.ID] {
			t.Errorf("session %s status = %q, want %q", session.ID, got, wantStatus[session.ID])
		}
	}

	// LoginType is carried through, which is the reason it was added to Session:
	// the broker applies per-login-type policy but did not record what it applied.
	if sessions[0].LoginType != "gui" {
		t.Errorf("login type = %q, want gui", sessions[0].LoginType)
	}
}

// ListSessions is the one place session state leaves the broker for human
// consumption, so it must not carry credentials — not the tokens (which live
// encrypted in the TokenManager) and not the ID that fetches them.
func TestSessionInfoCarriesNoTokenMaterial(t *testing.T) {
	infoType := reflect.TypeOf(SessionInfo{})
	for i := 0; i < infoType.NumField(); i++ {
		name := infoType.Field(i).Name
		if strings.Contains(name, "Token") {
			t.Errorf("SessionInfo.%s: a session listing must not carry token material", name)
		}
	}
}

func TestListSessionsOnEmptyBroker(t *testing.T) {
	if sessions := newAdminTestBroker(t).ListSessions(); len(sessions) != 0 {
		t.Errorf("got %d sessions from an empty broker, want 0", len(sessions))
	}
}

func TestListKeysIsSortedByUsername(t *testing.T) {
	broker := newAdminTestBroker(t)
	keyManager := sshpkg.NewKeyManager(t.TempDir())
	keyManager.SetKeySize(2048) // faster than the 4096-bit default; size is not what this asserts
	broker.keyManager = keyManager

	for _, username := range []string{"zoe", "alice"} {
		key, err := keyManager.GenerateKey(username)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", username, err)
		}
		if err := keyManager.SaveKey(username, key); err != nil {
			t.Fatalf("SaveKey(%s): %v", username, err)
		}
	}

	keys, unreadable, err := broker.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if unreadable != 0 {
		t.Errorf("unreadable = %d, want 0", unreadable)
	}
	if len(keys) != 2 || keys[0].Username != "alice" || keys[1].Username != "zoe" {
		t.Fatalf("got %+v, want alice then zoe", keys)
	}
}

func TestListKeysWithoutKeyManager(t *testing.T) {
	broker := newAdminTestBroker(t)

	keys, unreadable, err := broker.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys with no key manager should not error: %v", err)
	}
	if len(keys) != 0 || unreadable != 0 {
		t.Errorf("got %d keys / %d unreadable, want 0/0", len(keys), unreadable)
	}
}
