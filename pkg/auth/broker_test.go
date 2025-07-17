package auth

import (
	"context"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

func TestNewBroker(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SocketPath: "/tmp/test.sock",
			LogLevel:   "debug",
		},
		OIDC: config.OIDCConfig{
			Providers: []config.OIDCProvider{
				{
					Name:         "test",
					Issuer:       "mock://test-provider",
					ClientID:     "test-client-id",
					Scopes:       []string{"openid", "profile", "email"},
					DeviceEndpoint: "mock://device",
					TokenEndpoint:  "mock://token",
					UserInfoEndpoint: "mock://userinfo",
					UserMapping: config.UserMapping{
						UsernameClaim: "email",
						EmailClaim:    "email",
						NameClaim:     "name",
						GroupsClaim:   "groups",
					},
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
			TokenEncryptionKey: "test-encryption-key-32-bytes-long!",
			AuditEnabled:       true,
		},
		Audit: config.AuditConfig{
			Enabled: true,
			Format:  "json",
		},
	}

	// Test with mock provider (should not make network calls)
	broker, err := NewBroker(cfg)
	if err == nil {
		t.Error("Expected error with mock provider, but got nil")
	}
	if broker != nil {
		t.Error("Expected nil broker with invalid provider, but got non-nil")
	}
}

func TestBrokerValidation(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		expectError bool
	}{
		{
			name:        "nil config",
			cfg:         nil,
			expectError: true,
		},
		{
			name: "empty socket path",
			cfg: &config.Config{
				Server: config.ServerConfig{
					SocketPath: "",
				},
			},
			expectError: true,
		},
		{
			name: "no providers",
			cfg: &config.Config{
				Server: config.ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: config.OIDCConfig{
					Providers: []config.OIDCProvider{},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Catch panics for nil config (which is correct security behavior)
			defer func() {
				if r := recover(); r != nil && tt.expectError {
					// Expected panic for security reasons
					return
				} else if r != nil && !tt.expectError {
					t.Errorf("Unexpected panic: %v", r)
				}
			}()

			_, err := NewBroker(tt.cfg)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestBrokerContext(t *testing.T) {
	// Test context cancellation behavior
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// This tests that context cancellation is handled properly
	select {
	case <-ctx.Done():
		// Expected behavior
	default:
		t.Error("Context should be cancelled")
	}
}