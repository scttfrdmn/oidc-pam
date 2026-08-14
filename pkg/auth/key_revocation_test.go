package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
	oidcmetrics "github.com/scttfrdmn/oidc-pam/pkg/metrics"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
	sshpkg "github.com/scttfrdmn/oidc-pam/pkg/ssh"
)

// revokeTestEnv is a broker wired up for revocation only: real key storage, a real
// authorized_keys tree, and — the point of the fixture — a file-backed audit logger
// and a metrics registry, because #165 was a *reporting* defect. A disabled logger
// cannot show a revocation being claimed for a key that is still authorized.
type revokeTestEnv struct {
	broker    *Broker
	homeDir   string
	auditPath string
	registry  *prometheus.Registry
}

func newRevokeTestEnv(t *testing.T) *revokeTestEnv {
	t.Helper()

	// "sync" writes on the calling goroutine, so nothing is left buffered when
	// revokeSSHKey returns and the test never has to wait for a flush.
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
	keyManager.SetKeySize(2048) // this test is about bookkeeping, not RSA

	registry := prometheus.NewRegistry()
	homeDir := t.TempDir()

	broker := &Broker{
		config:                &config.Config{},
		sessions:              make(map[string]*Session),
		providers:             map[string]*OIDCProvider{},
		auditLogger:           auditLogger,
		keyManager:            keyManager,
		authorizedKeysManager: testAuthorizedKeysManager(t, homeDir, "alice", "bob", "carol"),
		metrics:               oidcmetrics.New(registry, nil),
	}

	return &revokeTestEnv{broker: broker, homeDir: homeDir, auditPath: auditPath, registry: registry}
}

// provision generates a key for a session and authorizes it, returning the session
// ready to be revoked.
func (e *revokeTestEnv) provision(t *testing.T, username string) *Session {
	t.Helper()

	return e.provisionSession(t, username, "a3f1c9d2e5b48706"+username)
}

// provisionSession is provision with the session ID chosen by the caller, for the
// case where one account has two sessions at once.
func (e *revokeTestEnv) provisionSession(t *testing.T, username, sessionID string) *Session {
	t.Helper()

	session := &Session{
		ID:           sessionID,
		UserID:       username,
		Email:        username + "@example.com",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
		LastAccessed: time.Now(),
		IsActive:     true,
	}
	sshKey, err := e.broker.generateSSHKey(session)
	if err != nil {
		t.Fatalf("generateSSHKey: %v", err)
	}
	session.SSHKeyID = sshKey.ID
	session.SSHPublicKey = sshKey.PublicKey
	return session
}

func (e *revokeTestEnv) authorizedKeys(t *testing.T, username string) string {
	t.Helper()

	path := filepath.Join(e.homeDir, username, ".ssh", "authorized_keys")
	data, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	return string(data)
}

// auditEventTypes returns the event types recorded so far, in order. Nil when
// nothing was recorded, so a test can assert on an absence.
func (e *revokeTestEnv) auditEventTypes(t *testing.T) []string {
	t.Helper()

	var types []string
	for _, event := range e.auditEvents(t) {
		types = append(types, event.EventType)
	}
	return types
}

func (e *revokeTestEnv) auditEvents(t *testing.T) []security.AuditEvent {
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

// revokeMetric returns the oidc_ssh_key_operations_total counter for
// operation="revoke" and the given result.
func (e *revokeTestEnv) revokeMetric(t *testing.T, result string) float64 {
	t.Helper()

	families, err := e.registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "oidc_ssh_key_operations_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			if labelsMatch(metric, map[string]string{"operation": "revoke", "result": result}) {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func labelsMatch(metric *dto.Metric, want map[string]string) bool {
	got := make(map[string]string, len(metric.GetLabel()))
	for _, label := range metric.GetLabel() {
		got[label.GetName()] = label.GetValue()
	}
	for name, value := range want {
		if got[name] != value {
			return false
		}
	}
	return true
}

// The positive control: a revocation that really removes the authorized_keys line
// is the only thing allowed to produce ssh_key_revoked.
func TestRevocationThatRemovesTheKeyIsAuditedAsSuccess(t *testing.T) {
	env := newRevokeTestEnv(t)
	session := env.provision(t, "alice")

	if err := env.broker.revokeSSHKey(session); err != nil {
		t.Fatalf("revokeSSHKey: %v", err)
	}

	if remaining := env.authorizedKeys(t, "alice"); strings.Contains(remaining, strings.TrimSpace(session.SSHPublicKey)) {
		t.Error("the revoked key is still in authorized_keys")
	}
	if got := env.auditEventTypes(t); !recorded(got, "ssh_key_revoked") {
		t.Errorf("a successful revocation recorded %v, want an ssh_key_revoked event", got)
	}
	if got := env.revokeMetric(t, "success"); got != 1 {
		t.Errorf("revoke success metric = %v, want 1", got)
	}
	if got := env.revokeMetric(t, "failure"); got != 0 {
		t.Errorf("revoke failure metric = %v, want 0", got)
	}
}

// #165: a removal that matched nothing must not be audited as a revocation. The
// entry is still in the file (or, as in the #165 sequence, fused with a comment and
// no longer matchable at all), so "SSH key revoked" would be a false statement in
// the record an operator is meant to trust.
func TestRevocationThatMatchesNothingIsNotAuditedAsSuccess(t *testing.T) {
	env := newRevokeTestEnv(t)
	session := env.provision(t, "bob")

	// Stand in for the state #165 produces: the line the broker would look for is
	// no longer there to be matched, but something is.
	path := filepath.Join(env.homeDir, "bob", ".ssh", "authorized_keys")
	survivor := strings.TrimSpace(session.SSHPublicKey) + "# Added by OIDC PAM on 2026-08-13 12:00:00\n"
	if err := os.WriteFile(path, []byte(survivor), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := env.broker.revokeSSHKey(session); err != nil {
		t.Fatalf("revokeSSHKey: %v", err)
	}

	types := env.auditEventTypes(t)
	if recorded(types, "ssh_key_revoked") {
		t.Errorf("the audit log claims ssh_key_revoked for a removal that matched nothing (#165); events: %v", types)
	}
	if !recorded(types, "ssh_key_revocation_incomplete") {
		t.Errorf("a revocation that removed nothing recorded %v, want an ssh_key_revocation_incomplete event", types)
	}
	for _, event := range env.auditEvents(t) {
		if event.EventType != "ssh_key_revocation_incomplete" {
			continue
		}
		if event.Success {
			t.Error("the incomplete-revocation event is marked successful")
		}
		if event.UserID != "bob" || event.SessionID != session.ID {
			t.Errorf("event does not identify the affected user and session: user_id=%q session_id=%q",
				event.UserID, event.SessionID)
		}
	}
	if got := env.revokeMetric(t, "success"); got != 0 {
		t.Errorf("revoke success metric = %v for a removal that matched nothing, want 0", got)
	}
	if got := env.revokeMetric(t, "failure"); got != 1 {
		t.Errorf("revoke failure metric = %v, want 1", got)
	}
	// The line that could not be revoked is still there; the audit trail now says so.
	if remaining := env.authorizedKeys(t, "bob"); !strings.Contains(remaining, "# Added by OIDC PAM") {
		t.Errorf("the unmatched line was removed after all; file is %q", remaining)
	}
}

// A second login supersedes the first: one live broker-issued key per account is
// the invariant, so the earlier entry is gone by the time the earlier session
// expires. That removal must not then be reported as a failure — it is the
// intended state, and calling it ssh_key_revocation_incomplete would train
// operators to ignore the one event that means a credential is still live (#165,
// #171).
func TestRevokingASupersededKeyIsNotReportedAsIncomplete(t *testing.T) {
	env := newRevokeTestEnv(t)

	first := env.provision(t, "carol")
	// A second login for the same account, with its own session ID, as the broker
	// mints them.
	second := env.provisionSession(t, "carol", "b7e4d5c6a1f09283b7e4d5c6a1f09283b7e4d5c6a1f09283b7e4d5c6a1f09283")

	remaining := env.authorizedKeys(t, "carol")
	if strings.Contains(remaining, strings.TrimSpace(first.SSHPublicKey)) {
		t.Fatalf("the first login's key is still authorized after a second login; the account "+
			"has two live broker keys (#171). File is %q", remaining)
	}
	if !strings.Contains(remaining, strings.TrimSpace(second.SSHPublicKey)) {
		t.Fatalf("the second login's key was not authorized; file is %q", remaining)
	}

	// Now the first session expires and its key is revoked. There is nothing left to
	// remove, but nothing is wrong either.
	if err := env.broker.revokeSSHKey(first); err != nil {
		t.Fatalf("revokeSSHKey: %v", err)
	}

	types := env.auditEventTypes(t)
	if recorded(types, "ssh_key_revocation_incomplete") {
		t.Errorf("revoking a key that a later login had already superseded was reported as an "+
			"incomplete revocation; events: %v", types)
	}
	if !recorded(types, "ssh_key_revoked") {
		t.Errorf("revoking a superseded key recorded %v, want ssh_key_revoked", types)
	}
	if got := env.revokeMetric(t, "failure"); got != 0 {
		t.Errorf("revoke failure metric = %v for a superseded key, want 0", got)
	}
	if got := env.revokeMetric(t, "success"); got != 1 {
		t.Errorf("revoke success metric = %v, want 1", got)
	}
	// The live login keeps working: revoking the older session must not disturb it.
	if after := env.authorizedKeys(t, "carol"); !strings.Contains(after, strings.TrimSpace(second.SSHPublicKey)) {
		t.Errorf("revoking the superseded key removed the live one; file is %q", after)
	}
}

func recorded(eventTypes []string, eventType string) bool {
	for _, t := range eventTypes {
		if t == eventType {
			return true
		}
	}
	return false
}
