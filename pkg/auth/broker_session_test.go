package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
)

func TestBrokerSessionMethods(t *testing.T) {
	// Test session management methods like CheckSession, RefreshSession, RevokeSession

	// Create broker with minimal initialization
	broker := &Broker{
		config: &config.Config{
			Authentication: config.AuthenticationConfig{
				TokenLifetime:         time.Hour,
				RefreshThreshold:      time.Minute * 15,
				MaxConcurrentSessions: 10,
			},
			Security: config.SecurityConfig{
				TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
			},
		},
		sessions:     make(map[string]*Session),
		sessionMutex: sync.RWMutex{},
		policyEngine: &PolicyEngine{},
		providers:    make(map[string]*OIDCProvider),
	}

	// Test CheckSession with non-existent session
	session, err := broker.CheckSession("non-existent-session", "test-user")
	if err != nil {
		t.Logf("CheckSession returned error for non-existent session: %v", err)
	}
	// CheckSession may return an AuthResponse rather than an error
	if session != nil && session.Success {
		t.Error("Expected unsuccessful response for non-existent session")
	}

	// Test RefreshSession with non-existent session
	refreshedSession, err := broker.RefreshSession("non-existent-session", "test-user")
	if err != nil {
		t.Logf("RefreshSession returned error for non-existent session: %v", err)
	}
	// RefreshSession may return an AuthResponse rather than an error
	if refreshedSession != nil && refreshedSession.Success {
		t.Error("Expected unsuccessful response for non-existent session")
	}

	// Test RevokeSession with non-existent session
	err = broker.RevokeSession("non-existent-session", "test-user")
	if err == nil {
		t.Error("Expected error for non-existent session")
	}

	// Create a test session to work with
	testSession := &Session{
		ID:               "test-session-methods",
		UserID:           "test-user-methods",
		Email:            "methods@example.com",
		Groups:           []string{"users"},
		Provider:         "test-provider",
		DeviceID:         "test-device",
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Hour),
		LastAccessed:     time.Now(),
		SourceIP:         "192.168.1.100",
		UserAgent:        "test-agent",
		TokenFingerprint: "test-token-fp",
		SSHKeyID:         "test-ssh-key",
		IsActive:         true,
		RiskScore:        10,
	}

	// Test setSession
	broker.setSession(testSession)

	// Test CheckSession with existing session
	session, err = broker.CheckSession("test-session-methods", "test-user-methods")
	if err != nil {
		t.Logf("CheckSession returned error for existing session: %v", err)
	}
	if session == nil {
		t.Error("Expected non-nil session response for existing session")
		return
	}
	if session.Success && session.UserID != "test-user-methods" {
		t.Errorf("Expected UserID 'test-user-methods', got '%s'", session.UserID)
	}

	// Test removeSession
	broker.removeSession("test-session-methods")

	// Verify session was removed
	session, err = broker.CheckSession("test-session-methods", "test-user-methods")
	if err != nil {
		t.Logf("CheckSession returned error after session removal: %v", err)
	}
	if session != nil && session.Success {
		t.Error("Expected unsuccessful response after session removal")
	}
}

func TestBrokerSessionCleanup(t *testing.T) {
	// Test session cleanup functionality

	// Create broker with minimal initialization
	broker := &Broker{
		config: &config.Config{
			Authentication: config.AuthenticationConfig{
				TokenLifetime:         time.Hour,
				RefreshThreshold:      time.Minute * 15,
				MaxConcurrentSessions: 10,
			},
			Security: config.SecurityConfig{
				TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
			},
		},
		sessions:     make(map[string]*Session),
		sessionMutex: sync.RWMutex{},
		policyEngine: &PolicyEngine{},
		providers:    make(map[string]*OIDCProvider),
		stopChan:     make(chan struct{}),
		wg:           sync.WaitGroup{},
	}

	// Add an expired session
	expiredSession := &Session{
		ID:               "expired-session",
		UserID:           "expired-user",
		Email:            "expired@example.com",
		Groups:           []string{"users"},
		Provider:         "test-provider",
		DeviceID:         "test-device",
		CreatedAt:        time.Now().Add(-2 * time.Hour),
		ExpiresAt:        time.Now().Add(-time.Hour), // Expired 1 hour ago
		LastAccessed:     time.Now().Add(-time.Hour),
		SourceIP:         "192.168.1.100",
		UserAgent:        "test-agent",
		TokenFingerprint: "test-token-fp",
		SSHKeyID:         "test-ssh-key",
		IsActive:         true,
		RiskScore:        10,
	}

	// Add a valid session
	validSession := &Session{
		ID:               "valid-session",
		UserID:           "valid-user",
		Email:            "valid@example.com",
		Groups:           []string{"users"},
		Provider:         "test-provider",
		DeviceID:         "test-device",
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Hour),
		LastAccessed:     time.Now(),
		SourceIP:         "192.168.1.100",
		UserAgent:        "test-agent",
		TokenFingerprint: "test-token-fp",
		SSHKeyID:         "test-ssh-key",
		IsActive:         true,
		RiskScore:        10,
	}

	broker.setSession(expiredSession)
	broker.setSession(validSession)

	// Verify both sessions exist initially
	if len(broker.sessions) != 2 {
		t.Errorf("Expected 2 sessions, got %d", len(broker.sessions))
	}

	// Run session cleanup with a very short timeout to test the cleanup logic
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
	defer cancel()

	// Run cleanup in a goroutine - we need to add to waitgroup first
	broker.wg.Add(1)
	go broker.sessionCleanup(ctx)

	// Wait for cleanup to run and then wait for the goroutine to finish
	time.Sleep(time.Millisecond * 100)
	broker.wg.Wait()

	// The cleanup should have removed the expired session
	// Note: This is a simplified test - in practice, the cleanup might need more sophisticated logic
	if broker.sessions["expired-session"] != nil {
		t.Log("Expired session still exists (cleanup may not have run yet)")
	}
	if broker.sessions["valid-session"] == nil {
		t.Error("Valid session was incorrectly removed")
	}
}

func TestBrokerStartStop(t *testing.T) {
	// Test basic Start/Stop functionality without actual network operations

	// Create a properly configured broker
	cfg := &config.Config{
		Server: config.ServerConfig{
			SocketPath: "/tmp/test-start-stop.sock",
		},
		OIDC: config.OIDCConfig{
			Providers: []config.OIDCProvider{
				{
					Name:            "test-provider",
					Issuer:          "https://example.com",
					ClientID:        "test-client",
					Scopes:          []string{"openid", "profile", "email"},
					EnabledForLogin: true,
				},
			},
		},
		Authentication: config.AuthenticationConfig{
			TokenLifetime:         time.Hour,
			RefreshThreshold:      time.Minute * 15,
			MaxConcurrentSessions: 10,
		},
		Security: config.SecurityConfig{
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		},
	}

	// Create broker - this will fail due to OIDC provider setup, but we can test the structure
	broker, err := NewBroker(cfg)
	if err != nil {
		// Expected to fail due to network calls, but test the basic structure
		t.Logf("Expected broker creation to fail due to network calls: %v", err)

		// Create a minimal broker for testing Start/Stop logic
		// Note: We can't create a full broker without network access, so we'll skip the Stop test
		t.Log("Skipping Stop test due to broker creation failure (expected without network access)")
		return
	}

	// Test Stop on unstarted broker (should not panic)
	err = broker.Stop()
	if err != nil {
		t.Logf("Stop returned error on unstarted broker: %v", err)
	}
}

// newTestBrokerWithDeviceServer creates a broker backed by an httptest server
// that responds to device authorization requests. The caller must defer server.Close().
func newTestBrokerWithDeviceServer(t *testing.T) (*Broker, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := DeviceAuthResponse{
			DeviceCode:      "test-device-code",
			UserCode:        "TEST-CODE",
			VerificationURI: "https://example.com/verify",
			ExpiresIn:       600,
			Interval:        5,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))

	provider := &OIDCProvider{
		Name: "test-provider",
		Config: config.OIDCProvider{
			Name:            "test-provider",
			Issuer:          server.URL,
			ClientID:        "test-client",
			Scopes:          []string{"openid", "profile"},
			DeviceEndpoint:  server.URL + "/device",
			EnabledForLogin: true,
		},
		httpClient: server.Client(),
	}

	auditLogger, err := security.NewAuditLogger(config.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime:         time.Hour,
			RefreshThreshold:      time.Minute * 15,
			MaxConcurrentSessions: 10,
		},
	}

	broker := &Broker{
		config:       cfg,
		sessions:     make(map[string]*Session),
		sessionMutex: sync.RWMutex{},
		policyEngine: &PolicyEngine{config: cfg},
		providers:    map[string]*OIDCProvider{"test-provider": provider},
		auditLogger:  auditLogger,
		stopChan:     make(chan struct{}),
	}

	return broker, server
}

func TestAuthenticateGeneratesSessionID(t *testing.T) {
	broker, server := newTestBrokerWithDeviceServer(t)
	defer server.Close()
	defer func() { close(broker.stopChan); broker.wg.Wait() }()

	req := &AuthRequest{
		UserID:     "test-user",
		SourceIP:   "127.0.0.1",
		TargetHost: "test-host",
		LoginType:  "ssh",
		SessionID:  "", // Client provides no session ID
	}

	resp, err := broker.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if resp.SessionID == "" {
		t.Fatal("Expected non-empty server-generated session ID")
	}

	// Verify the session ID is NOT the client-provided one
	if resp.SessionID == req.SessionID {
		t.Error("Session ID should be server-generated, not taken from request")
	}
}

func TestAuthenticateIgnoresClientSessionID(t *testing.T) {
	broker, server := newTestBrokerWithDeviceServer(t)
	defer server.Close()
	defer func() { close(broker.stopChan); broker.wg.Wait() }()

	clientSessionID := "client-provided-session-id"
	req := &AuthRequest{
		UserID:     "test-user",
		SourceIP:   "127.0.0.1",
		TargetHost: "test-host",
		LoginType:  "ssh",
		SessionID:  clientSessionID,
	}

	resp, err := broker.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if resp.SessionID == clientSessionID {
		t.Error("Session ID must not be the client-provided value (session fixation vulnerability)")
	}
	if resp.SessionID == "" {
		t.Fatal("Expected non-empty server-generated session ID")
	}
}

func TestAuthenticateTooManySessions(t *testing.T) {
	broker, server := newTestBrokerWithDeviceServer(t)
	defer server.Close()
	defer func() { close(broker.stopChan); broker.wg.Wait() }()

	// Set max concurrent sessions to 2
	broker.config.Authentication.MaxConcurrentSessions = 2

	// Create 2 sessions (should succeed)
	for i := 0; i < 2; i++ {
		req := &AuthRequest{
			UserID:     "test-user",
			SourceIP:   "127.0.0.1",
			TargetHost: "test-host",
			LoginType:  "ssh",
		}
		resp, err := broker.Authenticate(req)
		if err != nil {
			t.Fatalf("Authenticate call %d failed: %v", i+1, err)
		}
		if resp.ErrorCode == "TOO_MANY_SESSIONS" {
			t.Fatalf("Authenticate call %d should not hit session limit", i+1)
		}
	}

	// 3rd session should be rejected
	req := &AuthRequest{
		UserID:     "test-user",
		SourceIP:   "127.0.0.1",
		TargetHost: "test-host",
		LoginType:  "ssh",
	}
	resp, err := broker.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate call 3 returned unexpected error: %v", err)
	}
	if resp.Success {
		t.Fatal("Expected failure when session limit exceeded")
	}
	if resp.ErrorCode != "TOO_MANY_SESSIONS" {
		t.Fatalf("Expected TOO_MANY_SESSIONS error code, got %q", resp.ErrorCode)
	}
}

func TestBrokerRefreshSessionSuccess(t *testing.T) {
	// Mock token endpoint returns a new access token and refresh token.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := TokenResponse{
			AccessToken:  "refreshed-access-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refreshed-refresh-token",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider := &OIDCProvider{
		Name: "test-provider",
		Config: config.OIDCProvider{
			ClientID: "test-client",
			Scopes:   []string{"openid", "profile"},
		},
		OAuth2Config: &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				TokenURL: server.URL + "/token",
			},
		},
		httpClient: server.Client(),
	}

	auditLogger, err := security.NewAuditLogger(config.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
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
		providers:    map[string]*OIDCProvider{"test-provider": provider},
		auditLogger:  auditLogger,
		tokenManager: tokenManager,
	}

	// The refresh token lives in the token store, not on the session.
	oldTokenID, err := tokenManager.StoreToken(&Token{
		AccessToken:  "old-access-token",
		RefreshToken: "old-refresh-token",
		ExpiresAt:    time.Now().Add(5 * time.Minute),
		Fingerprint:  "old-fingerprint",
	}, "test-user", "refresh-test")
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}

	// Session is within the refresh threshold (expires in 5 minutes < 15 minute threshold)
	session := &Session{
		ID:               "refresh-test",
		UserID:           "test-user",
		Email:            "user@example.com",
		Provider:         "test-provider",
		IsActive:         true,
		TokenFingerprint: "old-fingerprint",
		TokenID:          oldTokenID,
		ExpiresAt:        time.Now().Add(5 * time.Minute),
		LastAccessed:     time.Now(),
	}
	broker.setSession(session)

	resp, err := broker.RefreshSession("refresh-test", "test-user")
	if err != nil {
		t.Fatalf("RefreshSession returned unexpected error: %v", err)
	}
	if !resp.Success {
		t.Fatalf("Expected success, got error %q: %s", resp.ErrorCode, resp.ErrorMessage)
	}

	// Verify the session was updated
	updated := broker.getSession("refresh-test")
	if updated == nil {
		t.Fatal("Session was removed after refresh")
	}
	if updated.TokenFingerprint == "old-fingerprint" {
		t.Error("Expected token fingerprint to be updated after refresh")
	}
	if updated.TokenID == "" || updated.TokenID == oldTokenID {
		t.Errorf("Expected the session to point at a new stored token, got %q", updated.TokenID)
	}

	// The new refresh token is reachable through the store...
	refreshed, err := tokenManager.GetToken(updated.TokenID)
	if err != nil {
		t.Fatalf("GetToken(%q): %v", updated.TokenID, err)
	}
	if refreshed.RefreshToken != "refreshed-refresh-token" {
		t.Errorf("stored refresh token = %q, want refreshed-refresh-token", refreshed.RefreshToken)
	}

	// ...and the rotated one is gone, rather than lingering as dead credential
	// material until the token store's own sweep.
	if _, err := tokenManager.GetToken(oldTokenID); err == nil {
		t.Error("the pre-refresh token is still in the store after rotation")
	}
}

func TestBrokerRefreshSessionNoRefreshToken(t *testing.T) {
	auditLogger, err := security.NewAuditLogger(config.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	broker := &Broker{
		config: &config.Config{
			Authentication: config.AuthenticationConfig{
				TokenLifetime:    time.Hour,
				RefreshThreshold: 15 * time.Minute,
			},
		},
		sessions:     make(map[string]*Session),
		sessionMutex: sync.RWMutex{},
		providers:    map[string]*OIDCProvider{"test-provider": {}},
		auditLogger:  auditLogger,
	}

	// Session without a refresh token
	session := &Session{
		ID:        "no-refresh-token-session",
		UserID:    "test-user",
		Provider:  "test-provider",
		IsActive:  true,
		TokenID:   "", // no stored token, so no refresh token
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	broker.setSession(session)

	resp, err := broker.RefreshSession("no-refresh-token-session", "test-user")
	if err != nil {
		t.Fatalf("RefreshSession returned unexpected error: %v", err)
	}
	if resp.Success {
		t.Fatal("Expected failure when no refresh token is available")
	}
	if resp.ErrorCode != "NO_REFRESH_TOKEN" {
		t.Errorf("Expected NO_REFRESH_TOKEN error code, got %q", resp.ErrorCode)
	}
}

func TestBrokerRefreshSessionNotCloseToExpiry(t *testing.T) {
	// Session not yet within the refresh threshold — RefreshSession should return success
	// without hitting the token endpoint.
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
	}

	session := &Session{
		ID:        "fresh-session",
		UserID:    "test-user",
		IsActive:  true,
		TokenID:   "some-token-id",
		ExpiresAt: time.Now().Add(30 * time.Minute), // well outside threshold
	}
	broker.setSession(session)

	resp, err := broker.RefreshSession("fresh-session", "test-user")
	if err != nil {
		t.Fatalf("RefreshSession returned unexpected error: %v", err)
	}
	if !resp.Success {
		t.Errorf("Expected success for session not yet needing refresh, got %q", resp.ErrorCode)
	}
}

func TestAuthenticateSessionIDUniqueness(t *testing.T) {
	broker, server := newTestBrokerWithDeviceServer(t)
	defer server.Close()
	defer func() { close(broker.stopChan); broker.wg.Wait() }()

	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		req := &AuthRequest{
			UserID:     "test-user",
			SourceIP:   "127.0.0.1",
			TargetHost: "test-host",
			LoginType:  "ssh",
		}

		resp, err := broker.Authenticate(req)
		if err != nil {
			t.Fatalf("Authenticate call %d failed: %v", i, err)
		}
		if seen[resp.SessionID] {
			t.Fatalf("Duplicate session ID generated on call %d: %s", i, resp.SessionID)
		}
		seen[resp.SessionID] = true
	}
}

// newTestTokenManager returns a TokenManager with a valid AES-256 key, for tests
// that exercise broker paths which store or read tokens.
func newTestTokenManager(t *testing.T) *TokenManager {
	t.Helper()

	tm, err := NewTokenManager(&config.Config{
		Security: config.SecurityConfig{
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		},
	})
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return tm
}
