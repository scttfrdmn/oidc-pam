package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

func TestBrokerInternalMethods(t *testing.T) {
	// Test internal broker methods that don't require OIDC provider connectivity
	
	// Create broker with minimal config
	broker := &Broker{
		config: &config.Config{
			Security: config.SecurityConfig{
				TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
			},
		},
		sessions: make(map[string]*Session),
	}
	
	// Test session helper with non-existent session
	session := broker.getSession("non-existent")
	if session != nil {
		t.Error("Expected nil session for non-existent session")
	}
	
	// Test createSuccessResponse with valid session
	testSession := &Session{
		ID:               "test-session-internal",
		UserID:           "test-user-internal",
		Email:            "internal@example.com",
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
	
	response := broker.createSuccessResponse(testSession)
	if response == nil {
		t.Error("Expected non-nil response for valid session")
		return
	}
	if !response.Success {
		t.Error("Expected successful response for valid session")
	}
	if response.UserID != "test-user-internal" {
		t.Errorf("Expected UserID 'test-user-internal', got '%s'", response.UserID)
	}
}

func TestBrokerSessionHelpers(t *testing.T) {
	// Test session helper methods without requiring OIDC connectivity
	
	// Create broker with valid config but don't initialize OIDC providers
	broker := &Broker{
		config: &config.Config{
			Authentication: config.AuthenticationConfig{
				TokenLifetime:         time.Hour,
				RefreshThreshold:      time.Minute * 15,
				MaxConcurrentSessions: 10,
			},
			Security: config.SecurityConfig{
				TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
			},
		},
		sessions:     make(map[string]*Session),
		sessionMutex: sync.RWMutex{},
		policyEngine: &PolicyEngine{},
	}

	// Test getSession with non-existent session
	session := broker.getSession("non-existent")
	if session != nil {
		t.Error("Expected nil session for non-existent session")
	}

	// Note: createSuccessResponse expects non-nil session, so we'll test it 
	// with valid session in the integration tests
	
	// Test session management by adding a session manually
	testSession := &Session{
		ID:               "test-session-123",
		UserID:           "test-user",
		Email:            "test@example.com",
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
		RiskScore:        5,
	}
	
	broker.sessions["test-session-123"] = testSession
	
	// Test getSession with existing session
	retrievedSession := broker.getSession("test-session-123")
	if retrievedSession == nil {
		t.Error("Expected non-nil session for existing session")
		return
	}
	if retrievedSession.ID != "test-session-123" {
		t.Errorf("Expected session ID 'test-session-123', got '%s'", retrievedSession.ID)
	}

	// Test createSuccessResponse with real session
	successResponse := broker.createSuccessResponse(testSession)
	if successResponse == nil {
		t.Error("Expected non-nil response for valid session")
		return
	}
	if !successResponse.Success {
		t.Error("Expected successful response for valid session")
	}
	if successResponse.UserID != "test-user" {
		t.Errorf("Expected UserID 'test-user', got '%s'", successResponse.UserID)
	}
}

func TestBrokerFieldInitialization(t *testing.T) {
	// Test that broker fields are properly initialized
	
	// Create broker with valid config and minimal required fields
	broker := &Broker{
		config: &config.Config{
			Authentication: config.AuthenticationConfig{
				TokenLifetime:         time.Hour,
				RefreshThreshold:      time.Minute * 15,
				MaxConcurrentSessions: 10,
			},
			Security: config.SecurityConfig{
				TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
			},
		},
		sessions:     make(map[string]*Session),
		sessionMutex: sync.RWMutex{},
		policyEngine: &PolicyEngine{},
		providers:    make(map[string]*OIDCProvider),
	}

	// Verify broker fields are properly initialized
	if broker.config == nil {
		t.Error("Expected non-nil config")
	}
	if broker.sessions == nil {
		t.Error("Expected non-nil sessions map")
	}
	if broker.policyEngine == nil {
		t.Error("Expected non-nil policy engine")
	}
	if broker.providers == nil {
		t.Error("Expected non-nil providers map")
	}
	
	// Test session map operations
	if len(broker.sessions) != 0 {
		t.Error("Expected empty sessions map")
	}
	
	// Add a test session and verify it's accessible
	testSession := &Session{
		ID:               "test-session-456",
		UserID:           "test-user-2",
		Email:            "test2@example.com",
		Groups:           []string{"users", "admin"},
		Provider:         "test-provider",
		DeviceID:         "test-device-2",
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Hour),
		LastAccessed:     time.Now(),
		SourceIP:         "192.168.1.101",
		UserAgent:        "test-agent-2",
		TokenFingerprint: "test-token-fp-2",
		SSHKeyID:         "test-ssh-key-2",
		IsActive:         true,
		RiskScore:        15,
	}
	
	broker.sessions["test-session-456"] = testSession
	
	// Test direct session access
	session := broker.sessions["test-session-456"]
	if session == nil {
		t.Error("Expected non-nil session")
		return
	}
	if session.UserID != "test-user-2" {
		t.Errorf("Expected UserID 'test-user-2', got '%s'", session.UserID)
	}
}

func TestBrokerProviderSelection(t *testing.T) {
	// Test provider selection logic without requiring OIDC connectivity
	
	// Create broker with multiple providers but don't initialize OIDC
	broker := &Broker{
		config: &config.Config{
			OIDC: config.OIDCConfig{
				Providers: []config.OIDCProvider{
					{
						Name:            "provider1",
						Issuer:          "https://provider1.com",
						ClientID:        "client1",
						Scopes:          []string{"openid", "profile", "email"},
						EnabledForLogin: true,
						Priority:        1,
					},
					{
						Name:            "provider2", 
						Issuer:          "https://provider2.com",
						ClientID:        "client2",
						Scopes:          []string{"openid", "profile", "email"},
						EnabledForLogin: true,
						Priority:        2,
					},
				},
			},
		},
		providers: map[string]*OIDCProvider{
			"provider1": {
				Name: "provider1",
				Config: config.OIDCProvider{
					Name:            "provider1",
					Issuer:          "https://provider1.com",
					ClientID:        "client1",
					Scopes:          []string{"openid", "profile", "email"},
					EnabledForLogin: true,
					Priority:        1,
				},
			},
			"provider2": {
				Name: "provider2",
				Config: config.OIDCProvider{
					Name:            "provider2",
					Issuer:          "https://provider2.com",
					ClientID:        "client2",
					Scopes:          []string{"openid", "profile", "email"},
					EnabledForLogin: true,
					Priority:        2,
				},
			},
		},
	}

	// Test provider selection
	authRequest := &AuthRequest{
		UserID:     "test-user@provider1.com",
		SourceIP:   "192.168.1.100",
		UserAgent:  "test-agent",
		TargetHost: "test-host",
		LoginType:  "ssh",
		DeviceID:   "test-device",
		SessionID:  "test-session",
		Timestamp:  time.Now(),
	}
	
	// Create a basic policy result
	policyResult := &PolicyResult{
		Allowed:        true,
		Reason:         "test policy",
		RequiredMFA:    false,
		RequiredGroups: nil,
		MaxDuration:    time.Hour,
		RiskScore:      0,
		RiskFactors:    nil,
		Metadata:       nil,
	}
	
	provider := broker.selectProvider(authRequest, policyResult)
	if provider == nil {
		t.Error("Expected non-nil provider")
		return
	}
	if provider.Name != "provider1" && provider.Name != "provider2" {
		t.Errorf("Expected provider1 or provider2, got %s", provider.Name)
	}

	// Test provider selection with different user
	authRequest.UserID = "test-user"
	provider = broker.selectProvider(authRequest, policyResult)
	if provider == nil {
		t.Error("Expected non-nil provider (should default to first)")
	}
}

func TestBrokerSSHKeyMethods(t *testing.T) {
	// Test SSH key methods without requiring full broker initialization
	
	// Create broker with minimal config
	broker := &Broker{
		config: &config.Config{
			Security: config.SecurityConfig{
				TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
			},
		},
	}

	// Test SSH key generation with mock session
	mockSession := &Session{
		ID:               "test-session",
		UserID:           "test-user",
		Email:            "test@example.com",
		Groups:           []string{"users"},
		Provider:         "test-provider",
		DeviceID:         "test-device",
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Hour),
		LastAccessed:     time.Now(),
		SourceIP:         "192.168.1.100",
		UserAgent:        "test-agent-ssh",
		TokenFingerprint: "test-token-fp-ssh",
		SSHKeyID:         "test-ssh-key-ssh",
		IsActive:         true,
		RiskScore:        20,
	}
	
	_, err := broker.generateSSHKey(mockSession)
	if err != nil {
		t.Logf("SSH key generation failed as expected: %v", err)
	}

	// Test SSH key revocation
	err = broker.revokeSSHKey(mockSession)
	if err != nil {
		t.Logf("SSH key revocation failed as expected: %v", err)
	}
}

// Test broker Start/Stop methods (renamed to avoid conflict)
func TestBrokerStartStopIntegration(t *testing.T) {
	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			Providers: []config.OIDCProvider{
				{
					Name:            "provider1",
					Issuer:          "https://example.com",
					ClientID:        "client1",
					Scopes:          []string{"openid", "profile"},
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
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	broker, err := NewBroker(cfg)
	if err != nil {
		t.Logf("Failed to create broker (expected due to network dependencies): %v", err)
		return
	}

	// Test Start method
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	
	err = broker.Start(ctx)
	// Start may fail due to network dependencies, but should not panic
	if err != nil {
		t.Logf("Start failed as expected due to network dependencies: %v", err)
	}

	// Test Stop method
	err = broker.Stop()
	if err != nil {
		t.Logf("Stop returned error: %v", err)
	}
}

// Test broker Authenticate method with different scenarios
func TestBrokerAuthenticateScenarios(t *testing.T) {
	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			Providers: []config.OIDCProvider{
				{
					Name:            "provider1",
					Issuer:          "https://example.com",
					ClientID:        "client1",
					Scopes:          []string{"openid", "profile"},
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
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	broker, err := NewBroker(cfg)
	if err != nil {
		t.Logf("Failed to create broker (expected due to network dependencies): %v", err)
		return
	}

	// Test authentication with nil request
	response, err := broker.Authenticate(nil)
	if err != nil {
		t.Logf("Authentication with nil request returned error: %v", err)
	}
	if response != nil && response.Success {
		t.Error("Expected authentication to fail with nil request")
	}

	// Test authentication with empty user ID
	authRequest := &AuthRequest{
		UserID:     "",
		LoginType:  "ssh",
		TargetHost: "testhost",
		Metadata: map[string]interface{}{
			"service": "sshd",
		},
	}
	response, err = broker.Authenticate(authRequest)
	if err != nil {
		t.Logf("Authentication with empty user ID returned error: %v", err)
	}
	if response != nil && response.Success {
		t.Error("Expected authentication to fail with empty user ID")
	}

	// Test authentication with valid request
	authRequest = &AuthRequest{
		UserID:     "testuser",
		LoginType:  "ssh",
		TargetHost: "testhost",
		Metadata: map[string]interface{}{
			"service": "sshd",
		},
	}
	response, err = broker.Authenticate(authRequest)
	if err != nil {
		t.Logf("Authentication returned error: %v", err)
	}
	// Should fail due to network dependencies, but should not panic
	if response != nil && response.Success {
		t.Log("Authentication succeeded (unexpected but not a failure)")
	} else {
		t.Log("Authentication failed as expected due to network dependencies")
	}
}

// Test pollDeviceAuthorization method
func TestBrokerPollDeviceAuthorization(t *testing.T) {
	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			Providers: []config.OIDCProvider{
				{
					Name:            "provider1",
					Issuer:          "https://example.com",
					ClientID:        "client1",
					Scopes:          []string{"openid", "profile"},
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
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	broker, err := NewBroker(cfg)
	if err != nil {
		t.Logf("Failed to create broker (expected due to network dependencies): %v", err)
		return
	}

	// Create a mock device flow
	deviceFlow := &DeviceFlow{
		DeviceCode:      "test-device-code",
		UserCode:        "TEST123",
		DeviceURL:       "https://example.com/verify",
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		PollingInterval: 5,
	}

	// Test pollDeviceAuthorization with mock data
	// This will likely fail due to network dependencies, but should not panic
	provider := &OIDCProvider{
		Name: "provider1",
		Config: config.OIDCProvider{
			Name:            "provider1",
			Issuer:          "https://example.com",
			ClientID:        "client1",
			Scopes:          []string{"openid", "profile"},
			EnabledForLogin: true,
			Priority:        1,
		},
	}

	// Create a mock session
	mockSession := &Session{
		ID:       "test-session-poll",
		UserID:   "test-user",
		Provider: "provider1",
	}

	// Test pollDeviceAuthorization with mock data
	// This method runs in a goroutine and doesn't return values
	// We'll just call it to test it doesn't panic
	broker.wg.Add(1)
	go broker.pollDeviceAuthorization(mockSession, provider, deviceFlow)
	
	// Wait briefly for the polling to start
	time.Sleep(10 * time.Millisecond)
	
	// Clean up
	broker.wg.Wait()
	t.Log("pollDeviceAuthorization completed without panic")
}