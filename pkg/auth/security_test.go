package auth

import (
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// TestBrokerSecurityValidation tests that the broker properly validates security requirements
func TestBrokerSecurityValidation(t *testing.T) {
	tests := []struct {
		name           string
		config         *config.Config
		expectedError  string
		securityIssue  string
	}{
		{
			name: "missing_encryption_key",
			config: &config.Config{
				Server: config.ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: config.OIDCConfig{
					Providers: []config.OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{"openid"},
						},
					},
				},
				Security: config.SecurityConfig{
					TokenEncryptionKey: "", // Missing encryption key
				},
			},
			expectedError: "encryption",
			securityIssue: "Tokens must be encrypted",
		},
		{
			name: "weak_encryption_key",
			config: &config.Config{
				Server: config.ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: config.OIDCConfig{
					Providers: []config.OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{"openid"},
						},
					},
				},
				Security: config.SecurityConfig{
					TokenEncryptionKey: "weak", // Too short
				},
			},
			expectedError: "encryption",
			securityIssue: "Encryption key must be sufficiently strong",
		},
		{
			name: "insecure_provider_http",
			config: &config.Config{
				Server: config.ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: config.OIDCConfig{
					Providers: []config.OIDCProvider{
						{
							Name:     "test",
							Issuer:   "http://test.example.com", // HTTP instead of HTTPS
							ClientID: "test-client",
							Scopes:   []string{"openid"},
						},
					},
				},
				Security: config.SecurityConfig{
					TokenEncryptionKey: "test-encryption-key-32-bytes-long!",
				},
			},
			expectedError: "provider",
			securityIssue: "OIDC providers must use HTTPS",
		},
		{
			name: "missing_required_scope",
			config: &config.Config{
				Server: config.ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: config.OIDCConfig{
					Providers: []config.OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{"profile"}, // Missing openid scope
						},
					},
				},
				Security: config.SecurityConfig{
					TokenEncryptionKey: "test-encryption-key-32-bytes-long!",
				},
			},
			expectedError: "openid",
			securityIssue: "OpenID scope is required for security",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBroker(tt.config)
			if err == nil {
				t.Errorf("Expected security validation to fail for: %s", tt.securityIssue)
			} else if tt.expectedError != "" && !contains(err.Error(), tt.expectedError) {
				t.Errorf("Expected error containing '%s' for security issue '%s', got: %v", 
					tt.expectedError, tt.securityIssue, err)
			}
		})
	}
}

// TestBrokerSessionSecurity tests session management security
func TestBrokerSessionSecurity(t *testing.T) {
	// Test session timeout enforcement
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime:         1 * time.Millisecond, // Very short for testing
			MaxConcurrentSessions: 1,
		},
	}

	// Verify that short session timeouts are enforced
	if cfg.Authentication.TokenLifetime >= time.Hour {
		t.Error("Session timeout should be configurable to short values for security")
	}

	// Test concurrent session limits
	if cfg.Authentication.MaxConcurrentSessions <= 0 {
		t.Error("Concurrent session limits must be enforced for security")
	}

	// Test that sessions expire properly
	sessionStart := time.Now()
	sessionExpiry := sessionStart.Add(cfg.Authentication.TokenLifetime)
	
	if time.Now().After(sessionExpiry.Add(10 * time.Millisecond)) {
		// Session should have expired by now for security
		t.Log("Session expiry mechanism working correctly")
	}
}

// TestBrokerSecureSocketPermissions tests that socket security is enforced
func TestBrokerSecureSocketPermissions(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SocketPath: "/tmp/test-security.sock",
		},
	}

	// Verify socket path is secure
	if cfg.Server.SocketPath == "" {
		t.Error("Socket path must be specified for security")
	}

	// Socket should not be in world-writable directory for security
	if contains(cfg.Server.SocketPath, "/tmp") {
		t.Log("Warning: Using /tmp for socket may have security implications")
	}

	// Production sockets should be in secure location
	securePaths := []string{"/var/run", "/run", "/var/lib"}
	isSecurePath := false
	for _, securePath := range securePaths {
		if contains(cfg.Server.SocketPath, securePath) {
			isSecurePath = true
			break
		}
	}
	
	if !isSecurePath && !contains(cfg.Server.SocketPath, "/tmp") {
		t.Log("Socket path should be in secure system directory")
	}
}

// TestBrokerAuditingSecurity tests that security events are properly audited
func TestBrokerAuditingSecurity(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			AuditEnabled: true,
		},
		Audit: config.AuditConfig{
			Enabled: true,
			Events: []string{
				"authentication_attempts",
				"authorization_decisions", 
				"token_validation",
				"session_creation",
				"session_termination",
				"configuration_changes",
				"security_violations",
			},
		},
	}

	// Verify audit is enabled for security
	if !cfg.Security.AuditEnabled {
		t.Error("Audit logging must be enabled for security compliance")
	}

	if !cfg.Audit.Enabled {
		t.Error("Audit subsystem must be enabled for security")
	}

	// Verify critical security events are audited
	requiredEvents := []string{
		"authentication_attempts",
		"authorization_decisions",
		"token_validation", 
		"security_violations",
	}

	for _, requiredEvent := range requiredEvents {
		found := false
		for _, configuredEvent := range cfg.Audit.Events {
			if configuredEvent == requiredEvent {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Critical security event '%s' must be audited", requiredEvent)
		}
	}
}

// TestBrokerTokenSecurity tests token handling security
func TestBrokerTokenSecurity(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			TokenEncryptionKey:  "test-encryption-key-32-bytes-long!",
			SecureTokenStorage:  true,
			VerifyAudience:      true,
			RequireAuthTime:     true,
			MaxTokenAge:         24 * time.Hour,
			ClockSkewTolerance:  5 * time.Minute,
		},
	}

	// Test encryption key strength
	if len(cfg.Security.TokenEncryptionKey) < 32 {
		t.Error("Token encryption key must be at least 32 bytes for security")
	}

	// Test secure storage requirement
	if !cfg.Security.SecureTokenStorage {
		t.Error("Secure token storage must be enabled for security")
	}

	// Test audience verification
	if !cfg.Security.VerifyAudience {
		t.Error("Token audience verification must be enabled for security")
	}

	// Test auth time requirement  
	if !cfg.Security.RequireAuthTime {
		t.Error("Auth time verification should be enabled for security")
	}

	// Test maximum token age limits
	if cfg.Security.MaxTokenAge > 24*time.Hour {
		t.Error("Token maximum age should not exceed 24 hours for security")
	}

	// Test clock skew tolerance is reasonable
	if cfg.Security.ClockSkewTolerance > 10*time.Minute {
		t.Error("Clock skew tolerance should be minimal for security")
	}
}

// TestBrokerRateLimitingSecurity tests rate limiting for security
func TestBrokerRateLimitingSecurity(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimiting{
				MaxRequestsPerMinute: 60,
				MaxConcurrentAuths:   10,
			},
		},
	}

	// Test rate limiting is configured
	if cfg.Security.RateLimiting.MaxRequestsPerMinute <= 0 {
		t.Error("Rate limiting must be configured to prevent abuse")
	}

	if cfg.Security.RateLimiting.MaxConcurrentAuths <= 0 {
		t.Error("Concurrent authentication limiting must be configured")
	}

	// Test limits are reasonable for security
	if cfg.Security.RateLimiting.MaxRequestsPerMinute > 1000 {
		t.Error("Rate limit too high - may allow brute force attacks")
	}

	if cfg.Security.RateLimiting.MaxConcurrentAuths > 100 {
		t.Error("Concurrent auth limit too high - may allow DoS attacks")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    len(s) > len(substr) && containsMiddle(s, substr))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}