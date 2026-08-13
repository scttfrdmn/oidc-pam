package auth

import (
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
)

// TestSessionHoldsNoTokenMaterial guards the invariant this file is about: a
// Session identifies its tokens (TokenID, TokenFingerprint) but never carries
// them. Session values are copied, logged and long-lived, and a refresh token is
// a standing credential that outlives the access token it renews — the whole
// point of encrypting the token store is undone if a plaintext copy also sits on
// the session.
//
// Session.RefreshToken existed until this was wired up, which is why the check is
// structural rather than a comment.
func TestSessionHoldsNoTokenMaterial(t *testing.T) {
	// TokenFingerprint is a hash, not a credential; TokenID is a store lookup key
	// with no value on its own.
	allowed := map[string]bool{
		"TokenFingerprint": true,
		"TokenID":          true,
	}

	sessionType := reflect.TypeOf(Session{})
	for i := 0; i < sessionType.NumField(); i++ {
		name := sessionType.Field(i).Name
		if allowed[name] {
			continue
		}
		if strings.Contains(name, "Token") {
			t.Errorf("Session.%s looks like token material; tokens belong in the "+
				"TokenManager, with only the ID on the session", name)
		}
	}
}

func newTokenTestBroker(t *testing.T) (*Broker, *TokenManager) {
	t.Helper()

	auditLogger, err := security.NewAuditLogger(config.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	tokenManager := newTestTokenManager(t)
	broker := &Broker{
		config: &config.Config{
			Authentication: config.AuthenticationConfig{
				TokenLifetime:    time.Hour,
				RefreshThreshold: 15 * time.Minute,
			},
		},
		sessions:     make(map[string]*Session),
		sessionMutex: sync.RWMutex{},
		providers:    map[string]*OIDCProvider{},
		auditLogger:  auditLogger,
		tokenManager: tokenManager,
	}
	return broker, tokenManager
}

// storeSessionWithToken registers a session that owns one stored token.
func storeSessionWithToken(t *testing.T, broker *Broker, tm *TokenManager, sessionID, userID string, expiresAt time.Time) string {
	t.Helper()

	tokenID, err := tm.StoreToken(&Token{
		AccessToken:  "access-" + sessionID,
		RefreshToken: "refresh-" + sessionID,
		ExpiresAt:    time.Now().Add(time.Hour),
		Fingerprint:  "fp-" + sessionID,
	}, userID, sessionID)
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}

	broker.setSession(&Session{
		ID:           sessionID,
		UserID:       userID,
		IsActive:     true,
		TokenID:      tokenID,
		ExpiresAt:    expiresAt,
		LastAccessed: time.Now(),
	})
	return tokenID
}

// A revoked session must take its tokens with it. Dropping only the session
// leaves a usable refresh token in the store until the token itself expires,
// which can be long after the session it was issued for.
func TestRevokeSessionDestroysItsStoredTokens(t *testing.T) {
	broker, tm := newTokenTestBroker(t)
	tokenID := storeSessionWithToken(t, broker, tm, "sess-revoke", "test-user", time.Now().Add(time.Hour))

	if _, err := tm.GetToken(tokenID); err != nil {
		t.Fatalf("token should exist before revocation: %v", err)
	}

	if err := broker.RevokeSession("sess-revoke", "test-user"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	if _, err := tm.GetToken(tokenID); err == nil {
		t.Error("session was revoked but its tokens are still in the store")
	}
	if total := tm.GetTokenStats()["total_tokens"].(int); total != 0 {
		t.Errorf("token store holds %d tokens after revoking the only session, want 0", total)
	}
}

// A refused cross-user revocation must not destroy the owner's tokens.
func TestRevokeSessionForWrongUserLeavesTokens(t *testing.T) {
	broker, tm := newTokenTestBroker(t)
	tokenID := storeSessionWithToken(t, broker, tm, "sess-owned", "owner", time.Now().Add(time.Hour))

	if err := broker.RevokeSession("sess-owned", "attacker"); err == nil {
		t.Fatal("expected cross-user revocation to be refused")
	}

	if _, err := tm.GetToken(tokenID); err != nil {
		t.Errorf("a refused revocation destroyed the owner's tokens: %v", err)
	}
	if broker.getSession("sess-owned") == nil {
		t.Error("a refused revocation removed the session")
	}
}

func TestExpiredSessionsHaveTheirTokensRevoked(t *testing.T) {
	broker, tm := newTokenTestBroker(t)

	expiredID := storeSessionWithToken(t, broker, tm, "sess-expired", "user-a", time.Now().Add(-time.Minute))
	liveID := storeSessionWithToken(t, broker, tm, "sess-live", "user-b", time.Now().Add(time.Hour))

	broker.expireSessions(time.Now())

	if broker.getSession("sess-expired") != nil {
		t.Error("expired session was not removed")
	}
	if _, err := tm.GetToken(expiredID); err == nil {
		t.Error("the expired session's tokens are still in the store")
	}

	if broker.getSession("sess-live") == nil {
		t.Fatal("the live session was removed")
	}
	if _, err := tm.GetToken(liveID); err != nil {
		t.Errorf("the live session's tokens were revoked: %v", err)
	}
}

// Idle expiry is a separate condition from absolute expiry, and it too must take
// the session's tokens with it.
func TestIdleSessionsHaveTheirTokensRevoked(t *testing.T) {
	broker, tm := newTokenTestBroker(t)
	broker.config.Authentication.IdleTimeout = 10 * time.Minute

	tokenID := storeSessionWithToken(t, broker, tm, "sess-idle", "user-a", time.Now().Add(time.Hour))
	session := broker.getSession("sess-idle")
	session.LastAccessed = time.Now().Add(-30 * time.Minute)
	broker.setSession(session)

	broker.expireSessions(time.Now())

	if broker.getSession("sess-idle") != nil {
		t.Error("idle session was not removed")
	}
	if _, err := tm.GetToken(tokenID); err == nil {
		t.Error("the idle session's tokens are still in the store")
	}
}
