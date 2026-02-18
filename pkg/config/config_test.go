package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary valid config file
	tempDir, err := os.MkdirTemp("", "config-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	configPath := filepath.Join(tempDir, "test.yaml")
	configContent := `
server:
  socket_path: "/tmp/test.sock"
  log_level: "info"
oidc:
  providers:
    - name: "test"
      issuer: "https://test.example.com"
      client_id: "test-client"
      scopes: ["openid", "profile"]
authentication:
  token_lifetime: "1h"
  refresh_threshold: "5m"
  max_concurrent_sessions: 10
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig returned nil config")
	}

	// Verify basic fields are loaded
	if cfg.Server.SocketPath != "/tmp/test.sock" {
		t.Errorf("Expected socket path '/tmp/test.sock', got '%s'", cfg.Server.SocketPath)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	// Create empty temp file to trigger environment loading
	tempDir, err := os.MkdirTemp("", "config-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Clean environment first
	_ = os.Unsetenv("OIDC_PROVIDER_URL")
	_ = os.Unsetenv("OIDC_CLIENT_ID")

	// Test that a valid minimal config loads
	validConfigPath := filepath.Join(tempDir, "valid.yaml")
	validContent := `
server:
  socket_path: "/tmp/test.sock"
oidc:
  providers:
    - name: "test"
      issuer: "https://test.example.com"
      client_id: "test-client"
      scopes: ["openid"]
authentication:
  token_lifetime: "1h"
  refresh_threshold: "5m"
  max_concurrent_sessions: 5
`
	if err := os.WriteFile(validConfigPath, []byte(validContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cfg, err := LoadConfig(validConfigPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify defaults are applied
	if cfg.Server.LogLevel != "info" {
		t.Errorf("Expected default log level 'info', got '%s'", cfg.Server.LogLevel)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{"openid", "profile"},
						},
					},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         time.Hour,
					RefreshThreshold:      time.Minute,
					MaxConcurrentSessions: 5,
				},
			},
			expectError: false,
		},
		{
			name: "missing socket path",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{"openid"},
						},
					},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         time.Hour,
					RefreshThreshold:      time.Minute,
					MaxConcurrentSessions: 5,
				},
			},
			expectError: true,
			errorMsg:    "socket_path is required",
		},
		{
			name: "no providers",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         time.Hour,
					RefreshThreshold:      time.Minute,
					MaxConcurrentSessions: 5,
				},
			},
			expectError: true,
			errorMsg:    "at least one OIDC provider",
		},
		{
			name: "provider missing name",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{
						{
							Name:     "",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{"openid"},
						},
					},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         time.Hour,
					RefreshThreshold:      time.Minute,
					MaxConcurrentSessions: 5,
				},
			},
			expectError: true,
			errorMsg:    "name is required",
		},
		{
			name: "provider missing issuer",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{
						{
							Name:     "test",
							Issuer:   "",
							ClientID: "test-client",
							Scopes:   []string{"openid"},
						},
					},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         time.Hour,
					RefreshThreshold:      time.Minute,
					MaxConcurrentSessions: 5,
				},
			},
			expectError: true,
			errorMsg:    "issuer is required",
		},
		{
			name: "provider missing client ID",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "",
							Scopes:   []string{"openid"},
						},
					},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         time.Hour,
					RefreshThreshold:      time.Minute,
					MaxConcurrentSessions: 5,
				},
			},
			expectError: true,
			errorMsg:    "client_id is required",
		},
		{
			name: "provider missing scopes",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{},
						},
					},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         time.Hour,
					RefreshThreshold:      time.Minute,
					MaxConcurrentSessions: 5,
				},
			},
			expectError: true,
			errorMsg:    "scopes is required",
		},
		{
			name: "provider missing openid scope",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{"profile", "email"},
						},
					},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         time.Hour,
					RefreshThreshold:      time.Minute,
					MaxConcurrentSessions: 5,
				},
			},
			expectError: true,
			errorMsg:    "must include 'openid'",
		},
		{
			name: "invalid token lifetime",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{"openid"},
						},
					},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         -time.Hour,
					RefreshThreshold:      time.Minute,
					MaxConcurrentSessions: 5,
				},
			},
			expectError: true,
			errorMsg:    "token_lifetime must be positive",
		},
		{
			name: "invalid refresh threshold",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{"openid"},
						},
					},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         time.Hour,
					RefreshThreshold:      -time.Minute,
					MaxConcurrentSessions: 5,
				},
			},
			expectError: true,
			errorMsg:    "refresh_threshold must be positive",
		},
		{
			name: "invalid max concurrent sessions",
			config: &Config{
				Server: ServerConfig{
					SocketPath: "/tmp/test.sock",
				},
				OIDC: OIDCConfig{
					Providers: []OIDCProvider{
						{
							Name:     "test",
							Issuer:   "https://test.example.com",
							ClientID: "test-client",
							Scopes:   []string{"openid"},
						},
					},
				},
				Authentication: AuthenticationConfig{
					TokenLifetime:         time.Hour,
					RefreshThreshold:      time.Minute,
					MaxConcurrentSessions: -5,
				},
			},
			expectError: true,
			errorMsg:    "max_concurrent_sessions must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Error("Expected validation error but got nil")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no validation error but got: %v", err)
				}
			}
		})
	}
}

func TestConfigDefaultValues(t *testing.T) {
	// Test that a minimal config gets proper defaults
	tempDir, err := os.MkdirTemp("", "config-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	configPath := filepath.Join(tempDir, "minimal.yaml")
	minimalContent := `
oidc:
  providers:
    - name: "test"
      issuer: "https://test.example.com"
      client_id: "test-client"
      scopes: ["openid"]
`
	if err := os.WriteFile(configPath, []byte(minimalContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Check that defaults are applied for missing values
	if cfg.Server.SocketPath != "/var/run/oidc-auth/broker.sock" {
		t.Errorf("Expected default socket path, got: %s", cfg.Server.SocketPath)
	}

	if cfg.Server.LogLevel != "info" {
		t.Errorf("Expected default log level 'info', got: %s", cfg.Server.LogLevel)
	}

	if cfg.Authentication.TokenLifetime != 8*time.Hour {
		t.Errorf("Expected default token lifetime 8h, got: %v", cfg.Authentication.TokenLifetime)
	}

	if cfg.Authentication.MaxConcurrentSessions != 10 {
		t.Errorf("Expected default max sessions 10, got: %d", cfg.Authentication.MaxConcurrentSessions)
	}
}

func TestSecurityConfigValidation(t *testing.T) {
	// Ensure dev mode is off for these tests
	t.Setenv("OIDC_AUTH_DEV", "")

	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "secure defaults pass",
			config: &Config{
				Security: SecurityConfig{
					SecureTokenStorage: true,
					VerifyAudience:     true,
					RequirePKCE:        true,
					TLSVerification:    TLSVerification{SkipTLSVerify: false},
				},
			},
			expectError: false,
		},
		{
			name: "secure_token_storage disabled fails",
			config: &Config{
				Security: SecurityConfig{
					SecureTokenStorage: false,
					VerifyAudience:     true,
					RequirePKCE:        true,
					TLSVerification:    TLSVerification{SkipTLSVerify: false},
				},
			},
			expectError: true,
			errorMsg:    "secure_token_storage must be enabled",
		},
		{
			name: "verify_audience disabled fails",
			config: &Config{
				Security: SecurityConfig{
					SecureTokenStorage: true,
					VerifyAudience:     false,
					RequirePKCE:        true,
					TLSVerification:    TLSVerification{SkipTLSVerify: false},
				},
			},
			expectError: true,
			errorMsg:    "verify_audience must be enabled",
		},
		{
			name: "require_pkce disabled fails",
			config: &Config{
				Security: SecurityConfig{
					SecureTokenStorage: true,
					VerifyAudience:     true,
					RequirePKCE:        false,
					TLSVerification:    TLSVerification{SkipTLSVerify: false},
				},
			},
			expectError: true,
			errorMsg:    "require_pkce must be enabled",
		},
		{
			name: "skip_tls_verify enabled fails",
			config: &Config{
				Security: SecurityConfig{
					SecureTokenStorage: true,
					VerifyAudience:     true,
					RequirePKCE:        true,
					TLSVerification:    TLSVerification{SkipTLSVerify: true},
				},
			},
			expectError: true,
			errorMsg:    "skip_tls_verify must be disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecurityConfig(tt.config)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestSecurityConfigValidationDevMode(t *testing.T) {
	t.Setenv("OIDC_AUTH_DEV", "true")

	// All weakened settings should pass in dev mode (warnings only, no errors)
	cfg := &Config{
		Security: SecurityConfig{
			SecureTokenStorage: false,
			VerifyAudience:     false,
			RequirePKCE:        false,
			TLSVerification:    TLSVerification{SkipTLSVerify: true},
		},
	}

	if err := validateSecurityConfig(cfg); err != nil {
		t.Errorf("Expected no error in dev mode, got: %v", err)
	}
}

func TestEnvironmentVariableOverrides(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-env-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	configPath := filepath.Join(tempDir, "test.yaml")
	configContent := `
server:
  socket_path: "/tmp/test.sock"
  log_level: "info"
oidc:
  providers:
    - name: "test"
      issuer: "https://test.example.com"
      client_id: "test-client"
      scopes: ["openid", "profile"]
authentication:
  token_lifetime: "1h"
  refresh_threshold: "5m"
  max_concurrent_sessions: 10
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	t.Run("safe env vars work", func(t *testing.T) {
		t.Setenv("OIDC_AUTH_DEV", "")
		t.Setenv("OIDC_AUTH_SERVER_LOG_LEVEL", "debug")

		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}

		if cfg.Server.LogLevel != "debug" {
			t.Errorf("Expected log_level 'debug' from env override, got %q", cfg.Server.LogLevel)
		}
	})

	t.Run("security env vars ignored in production", func(t *testing.T) {
		t.Setenv("OIDC_AUTH_DEV", "")
		t.Setenv("OIDC_AUTH_SECURITY_SECURE_TOKEN_STORAGE", "false")
		t.Setenv("OIDC_AUTH_SECURITY_VERIFY_AUDIENCE", "false")
		t.Setenv("OIDC_AUTH_SECURITY_REQUIRE_PKCE", "false")

		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}

		// Security settings should retain their defaults (true), not the env override
		if !cfg.Security.SecureTokenStorage {
			t.Error("secure_token_storage should not be overridden by env var in production")
		}
		if !cfg.Security.VerifyAudience {
			t.Error("verify_audience should not be overridden by env var in production")
		}
		if !cfg.Security.RequirePKCE {
			t.Error("require_pkce should not be overridden by env var in production")
		}
	})

	t.Run("security env vars allowed in dev mode", func(t *testing.T) {
		t.Setenv("OIDC_AUTH_DEV", "true")
		t.Setenv("OIDC_AUTH_SECURITY_SECURE_TOKEN_STORAGE", "false")
		t.Setenv("OIDC_AUTH_SECURITY_VERIFY_AUDIENCE", "false")
		t.Setenv("OIDC_AUTH_SECURITY_REQUIRE_PKCE", "false")

		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}

		// In dev mode, security env vars should take effect
		if cfg.Security.SecureTokenStorage {
			t.Error("secure_token_storage should be overridden by env var in dev mode")
		}
		if cfg.Security.VerifyAudience {
			t.Error("verify_audience should be overridden by env var in dev mode")
		}
		if cfg.Security.RequirePKCE {
			t.Error("require_pkce should be overridden by env var in dev mode")
		}
	})
}

func TestDevelopmentModeDetection(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{"true", "true", true},
		{"TRUE", "TRUE", true},
		{"True", "True", true},
		{"1", "1", true},
		{"yes", "yes", true},
		{"YES", "YES", true},
		{"false", "false", false},
		{"0", "0", false},
		{"no", "no", false},
		{"empty", "", false},
		{"random", "random", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OIDC_AUTH_DEV", tt.envValue)
			if got := isDevelopmentMode(); got != tt.expected {
				t.Errorf("isDevelopmentMode() with OIDC_AUTH_DEV=%q = %v, want %v", tt.envValue, got, tt.expected)
			}
		})
	}
}
