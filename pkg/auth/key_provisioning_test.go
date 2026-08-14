package auth

import (
	"context"
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

// These tests cover #171: the SSH key the broker hands out has to actually be
// installed where sshd will read it, has to stop working when the session ends, and
// must not be reported as working when it is not.

// A login whose key could not be installed is a login that cannot be used. It used
// to be completed anyway: the session was activated and the flow recorded
// authentication_successful, so the user was told they were authenticated and then
// found they could not log in — with the broker's own log the only place the reason
// existed.
func TestLoginIsDeniedWhenTheKeyCannotBeProvisioned(t *testing.T) {
	env := newPollTestEnv(t)

	// Provisioning fails for a reason an operator really hits: the account's home
	// directory is not present on this host. The broker must refuse rather than
	// create one (as root, mode 0700) and claim success.
	if err := os.RemoveAll(filepath.Join(env.homeDir, env.session.UserID)); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	env.idp.Script(testoidc.Grant)
	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("the session was activated although no key could be installed: %+v", session)
	}

	types := map[string]int{}
	for _, event := range env.auditEvents(t) {
		types[event.EventType]++
	}
	if types["ssh_key_provisioning_failed"] != 1 {
		t.Errorf("want exactly one ssh_key_provisioning_failed event, got %d (events: %v)",
			types["ssh_key_provisioning_failed"], types)
	}
	if types["authentication_successful"] != 0 {
		t.Error("a login whose SSH key could not be installed was recorded as successful, " +
			"so the audit trail says the user has access they do not have")
	}
	// Nothing may have been left in the account's place either.
	if _, err := os.Stat(filepath.Join(env.homeDir, env.session.UserID)); err == nil {
		t.Error("the broker created the missing home directory")
	}
}

// The stored key pair and the authorized_keys entry have to agree: a stored key
// with no entry authorizes nothing, and an entry with no stored key can never be
// revoked. A failure to write the store must therefore also deny the login.
func TestLoginIsDeniedWhenTheKeyStoreCannotBeWritten(t *testing.T) {
	env := newPollTestEnv(t)

	// Point the key store at a path that cannot hold it: a regular file.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	env.broker.keyManager = sshpkg.NewKeyManager(blocked)
	env.broker.keyManager.SetKeySize(2048)

	env.idp.Script(testoidc.Grant)
	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("the session was activated although the key pair could not be stored: %+v", session)
	}
	authorizedKeys := filepath.Join(env.homeDir, env.session.UserID, ".ssh", "authorized_keys")
	if data, err := os.ReadFile(authorizedKeys); err == nil && strings.Contains(string(data), "@oidc-pam-") {
		t.Errorf("a key was authorized that the broker cannot revoke, since it was never stored:\n%s", data)
	}
}

// newReconcileBroker returns a broker with a real key store and an
// authorized_keys manager rooted at a temporary tree, ready for Start().
func newReconcileBroker(t *testing.T, homeDir string, usernames ...string) *Broker {
	t.Helper()

	auditLogger, err := security.NewAuditLogger(config.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	keyManager := sshpkg.NewKeyManager(t.TempDir())
	keyManager.SetKeySize(2048)

	return &Broker{
		config: &config.Config{
			Authentication: config.AuthenticationConfig{TokenLifetime: time.Hour},
		},
		providers:             map[string]*OIDCProvider{},
		tokenManager:          newTestTokenManager(t),
		policyEngine:          &PolicyEngine{},
		auditLogger:           auditLogger,
		sessions:              make(map[string]*Session),
		keyManager:            keyManager,
		authorizedKeysManager: testAuthorizedKeysManager(t, homeDir, usernames...),
		stopChan:              make(chan struct{}),
	}
}

// The keys of a broker that has stopped are orphans: sessions live only in memory,
// so after a restart nothing remains that would ever revoke them, while the
// authorized_keys entries keep authenticating. Starting up must revoke them.
//
// This drives Start(), not the reconciliation helper directly, because "it happens
// at startup" is the claim — a helper nothing calls is exactly the shape of the
// defect (RemoveExpiredKeys was reachable and unreachable for the same reason).
func TestStartupRevokesKeysLeftByAPreviousRun(t *testing.T) {
	homeDir := t.TempDir()
	broker := newReconcileBroker(t, homeDir, "alice")

	// What a previous run left behind: a key pair in the store, and its entry in the
	// user's authorized_keys, with no session anywhere.
	orphan, err := broker.keyManager.GenerateKey("alice")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const orphanSessionID = "1f2e3d4c5b6a79880f1e2d3c4b5a69780f1e2d3c4b5a69780f1e2d3c4b5a6978"
	if err := broker.keyManager.SaveKey(orphanSessionID, orphan); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}
	own := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5OWN personal-laptop"
	path := writeAuthorizedKeys(t, homeDir, "alice",
		"# Added by OIDC PAM on 2026-01-01 00:00:00",
		fmt.Sprintf(`expiry-time="%s" %s`,
			time.Now().Add(time.Hour).UTC().Format("20060102150405Z"),
			strings.TrimSpace(string(orphan.PublicKey))),
		own)

	if err := broker.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = broker.Stop() })

	remaining := readAuthorizedKeys(t, path)
	if strings.Contains(remaining, strings.TrimSpace(string(orphan.PublicKey))) {
		t.Errorf("a key issued before the restart still authorizes access, and no session "+
			"remains that would ever revoke it (#171); file is %q", remaining)
	}
	if !strings.Contains(remaining, own) {
		t.Errorf("the user's own key was removed; file is %q", remaining)
	}
	// The stored pair goes too: leaving it would make the next startup try again
	// forever, and the private half is a live credential on disk.
	if _, err := broker.keyManager.LoadKey(orphanSessionID); err == nil {
		t.Error("the orphaned key pair is still in the broker's key store")
	}
}

// Reconciliation must not touch a user whose only broker entry is the one this run
// is about to issue — but there is no such user at startup, so the case to pin is
// the empty store: a broker with nothing stored must leave every authorized_keys
// file alone.
func TestStartupLeavesAuthorizedKeysAloneWhenTheStoreIsEmpty(t *testing.T) {
	homeDir := t.TempDir()
	broker := newReconcileBroker(t, homeDir, "alice")

	// A key bearing the marker that this broker did *not* issue — a different host's
	// broker writing a shared NFS home, say. With nothing in the store there is
	// nothing to reconcile and nothing to remove.
	line := "ssh-rsa AAAAB3NzaC1yc2EOTHERHOST alice@oidc-pam-1700000000"
	path := writeAuthorizedKeys(t, homeDir, "alice", line)

	if err := broker.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = broker.Stop() })

	if got := readAuthorizedKeys(t, path); !strings.Contains(got, "OTHERHOST") {
		t.Errorf("startup rewrote authorized_keys with an empty key store; file is %q", got)
	}
}

// The configured token lifetime is what limits a key. Both the key store and the
// authorized_keys sweep defaulted to 24 hours and neither was ever told the
// configured value, so a site with token_lifetime: 30m still issued keys good for a
// day (#171).
func TestConfiguredTokenLifetimeLimitsTheIssuedKey(t *testing.T) {
	const lifetime = 30 * time.Minute

	// The real constructor, against an in-process issuer, because the claim is about
	// what NewBroker wires up — the managers it builds are unexported and reached no
	// other way.
	const clientID = "oidc-pam-test-client"
	idp := testoidc.New(t, clientID)

	broker, err := NewBroker(&config.Config{
		Server: config.ServerConfig{SocketPath: filepath.Join(t.TempDir(), "broker.sock")},
		OIDC: config.OIDCConfig{
			Providers: []config.OIDCProvider{{
				Name:            "testidp",
				Issuer:          idp.Issuer(),
				ClientID:        clientID,
				Scopes:          []string{"openid", "profile", "email"},
				EnabledForLogin: true,
			}},
		},
		Security: config.SecurityConfig{
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		},
		Authentication: config.AuthenticationConfig{TokenLifetime: lifetime},
		Audit:          config.AuditConfig{Enabled: false},
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}

	broker.keyManager.SetKeySize(2048)
	key, err := broker.keyManager.GenerateKey("alice")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	got := time.Until(key.ExpiresAt)
	if got > lifetime+time.Minute {
		t.Errorf("a key issued under token_lifetime=%s expires in %s; the configured lifetime "+
			"is not what limits the key", lifetime, got.Round(time.Second))
	}
	if got < lifetime-time.Minute {
		t.Errorf("a key issued under token_lifetime=%s expires in %s, sooner than the session "+
			"it belongs to", lifetime, got.Round(time.Second))
	}
}
