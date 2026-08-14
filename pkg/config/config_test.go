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

func TestResolveSecretReferences(t *testing.T) {
	// Test env: prefix
	t.Run("env prefix", func(t *testing.T) {
		t.Setenv("TEST_SECRET_VALUE", "resolved-secret")

		cfg := &Config{
			OIDC: OIDCConfig{
				Providers: []OIDCProvider{
					{Name: "test", ClientSecret: "env:TEST_SECRET_VALUE"},
				},
			},
			Security: SecurityConfig{
				TokenEncryptionKey: "env:TEST_SECRET_VALUE",
			},
		}

		if err := resolveSecretReferences(cfg); err != nil {
			t.Fatalf("resolveSecretReferences failed: %v", err)
		}

		if cfg.OIDC.Providers[0].ClientSecret != "resolved-secret" {
			t.Errorf("Expected client_secret 'resolved-secret', got %q", cfg.OIDC.Providers[0].ClientSecret)
		}
		if cfg.Security.TokenEncryptionKey != "resolved-secret" {
			t.Errorf("Expected token_encryption_key 'resolved-secret', got %q", cfg.Security.TokenEncryptionKey)
		}
	})

	// Test file: prefix
	t.Run("file prefix", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "secret-test-*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer func() { _ = os.RemoveAll(tempDir) }()

		secretPath := filepath.Join(tempDir, "secret.txt")
		if err := os.WriteFile(secretPath, []byte("  file-secret-value\n"), 0600); err != nil {
			t.Fatalf("Failed to write secret file: %v", err)
		}

		cfg := &Config{
			OIDC: OIDCConfig{
				Providers: []OIDCProvider{
					{Name: "test", ClientSecret: "file:" + secretPath},
				},
			},
			Security: SecurityConfig{
				TokenEncryptionKey: "plain-key-value",
			},
		}

		if err := resolveSecretReferences(cfg); err != nil {
			t.Fatalf("resolveSecretReferences failed: %v", err)
		}

		if cfg.OIDC.Providers[0].ClientSecret != "file-secret-value" {
			t.Errorf("Expected trimmed file secret 'file-secret-value', got %q", cfg.OIDC.Providers[0].ClientSecret)
		}
	})

	// Test plain values pass through
	t.Run("plain values", func(t *testing.T) {
		cfg := &Config{
			OIDC: OIDCConfig{
				Providers: []OIDCProvider{
					{Name: "test", ClientSecret: "plain-secret"},
				},
			},
			Security: SecurityConfig{
				TokenEncryptionKey: "plain-key",
			},
		}

		if err := resolveSecretReferences(cfg); err != nil {
			t.Fatalf("resolveSecretReferences failed: %v", err)
		}

		if cfg.OIDC.Providers[0].ClientSecret != "plain-secret" {
			t.Errorf("Expected plain-secret, got %q", cfg.OIDC.Providers[0].ClientSecret)
		}
		if cfg.Security.TokenEncryptionKey != "plain-key" {
			t.Errorf("Expected plain-key, got %q", cfg.Security.TokenEncryptionKey)
		}
	})

	// Test empty values pass through
	t.Run("empty values", func(t *testing.T) {
		cfg := &Config{
			OIDC: OIDCConfig{
				Providers: []OIDCProvider{
					{Name: "test", ClientSecret: ""},
				},
			},
			Security: SecurityConfig{
				TokenEncryptionKey: "",
			},
		}

		if err := resolveSecretReferences(cfg); err != nil {
			t.Fatalf("resolveSecretReferences failed: %v", err)
		}
	})
}

func TestResolveSecretReferenceErrors(t *testing.T) {
	// Test missing env var
	t.Run("missing env var", func(t *testing.T) {
		t.Setenv("NONEXISTENT_SECRET", "")
		_ = os.Unsetenv("NONEXISTENT_SECRET")

		cfg := &Config{
			OIDC: OIDCConfig{
				Providers: []OIDCProvider{
					{Name: "test", ClientSecret: "env:NONEXISTENT_SECRET"},
				},
			},
		}

		err := resolveSecretReferences(cfg)
		if err == nil {
			t.Error("Expected error for missing env var")
		} else if !strings.Contains(err.Error(), "not set or empty") {
			t.Errorf("Expected 'not set or empty' in error, got: %v", err)
		}
	})

	// Test missing file
	t.Run("missing file", func(t *testing.T) {
		cfg := &Config{
			OIDC: OIDCConfig{
				Providers: []OIDCProvider{
					{Name: "test", ClientSecret: "file:/nonexistent/path/secret.txt"},
				},
			},
		}

		err := resolveSecretReferences(cfg)
		if err == nil {
			t.Error("Expected error for missing file")
		} else if !strings.Contains(err.Error(), "failed to read secret file") {
			t.Errorf("Expected 'failed to read secret file' in error, got: %v", err)
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

// TestUserMappingDomainPinValidation covers the config half of #159: an operator
// who turns on local-part binding without pinning the domains it may come from has
// re-opened the hole the pin exists to close, and finds out when the broker starts
// rather than when someone discovers what it admits.
func TestUserMappingDomainPinValidation(t *testing.T) {
	withMapping := func(m UserMapping) *Config {
		return &Config{
			Server: ServerConfig{SocketPath: "/tmp/test.sock"},
			OIDC: OIDCConfig{Providers: []OIDCProvider{{
				Name:        "test",
				Issuer:      "https://test.example.com",
				ClientID:    "test-client",
				Scopes:      []string{"openid"},
				UserMapping: m,
			}}},
			Authentication: AuthenticationConfig{
				TokenLifetime:         time.Hour,
				RefreshThreshold:      time.Minute,
				MaxConcurrentSessions: 5,
			},
		}
	}

	tests := []struct {
		name    string
		mapping UserMapping
		wantErr string
	}{
		{
			name:    "off by default needs no domains",
			mapping: UserMapping{UsernameClaim: "email"},
		},
		{
			name:    "opted in with a pinned domain",
			mapping: UserMapping{UsernameClaim: "email", StripEmailDomain: true, AllowedEmailDomains: []string{"example.com"}},
		},
		{
			name:    "opted in with no domains",
			mapping: UserMapping{UsernameClaim: "email", StripEmailDomain: true},
			wantErr: "no allowed_email_domains",
		},
		{
			name:    "wildcard domain refused",
			mapping: UserMapping{UsernameClaim: "email", StripEmailDomain: true, AllowedEmailDomains: []string{"*.example.com"}},
			wantErr: "wildcard",
		},
		{
			name:    "an address instead of a domain",
			mapping: UserMapping{UsernameClaim: "email", StripEmailDomain: true, AllowedEmailDomains: []string{"alice@example.com"}},
			wantErr: "looks like an address",
		},
		{
			name:    "empty domain entry",
			mapping: UserMapping{UsernameClaim: "email", StripEmailDomain: true, AllowedEmailDomains: []string{"example.com", "  "}},
			wantErr: "empty entry",
		},
		{
			// Domains listed without the opt-in are inert, not an error: an operator
			// staging the pin before flipping the switch is not misconfigured.
			name:    "domains without the opt-in are allowed",
			mapping: UserMapping{UsernameClaim: "email", AllowedEmailDomains: []string{"example.com"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := withMapping(tc.mapping).Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("Validate() = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestShippedConfigsPinTheirDomains asserts the configs in configs/ satisfy the
// rule above. They were all written when local-part binding was unconditional, so
// they are exactly the population at risk of shipping a config that either cannot
// log anyone in or admits any domain.
func TestShippedConfigsPinTheirDomains(t *testing.T) {
	paths, err := filepath.Glob("../../configs/**/*.yaml")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	more, _ := filepath.Glob("../../configs/*.yaml")
	paths = append(paths, more...)
	if len(paths) == 0 {
		t.Skip("no shipped configs found from this working directory")
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		text := string(data)
		if !strings.Contains(text, "username_claim_strip_domain") {
			continue
		}
		if !strings.Contains(text, "allowed_email_domains") {
			t.Errorf("%s enables username_claim_strip_domain without allowed_email_domains", path)
		}
	}
}
