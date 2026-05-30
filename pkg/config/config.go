package config

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the complete configuration for the OIDC PAM broker
type Config struct {
	Server         ServerConfig         `mapstructure:"server"`
	OIDC           OIDCConfig           `mapstructure:"oidc"`
	Authentication AuthenticationConfig `mapstructure:"authentication"`
	Security       SecurityConfig       `mapstructure:"security"`
	Cloud          CloudConfig          `mapstructure:"cloud"`
	Audit          AuditConfig          `mapstructure:"audit"`
}

// ServerConfig contains server-specific configuration
type ServerConfig struct {
	SocketPath      string        `mapstructure:"socket_path"`
	SocketMode      os.FileMode   `mapstructure:"socket_mode"`
	SocketGroup     string        `mapstructure:"socket_group"`
	RequirePeerAuth bool          `mapstructure:"require_peer_auth"`
	LogLevel        string        `mapstructure:"log_level"`
	AuditLog        string        `mapstructure:"audit_log"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	// MetricsAddr is the TCP address on which the /metrics HTTP endpoint is
	// served for Prometheus scraping (e.g. ":9090").  Leave empty to disable.
	MetricsAddr string `mapstructure:"metrics_addr"`
}

// OIDCConfig contains OIDC provider configuration
type OIDCConfig struct {
	Providers []OIDCProvider `mapstructure:"providers"`
}

// OIDCProvider represents a single OIDC provider configuration
type OIDCProvider struct {
	Name              string            `mapstructure:"name"`
	Issuer            string            `mapstructure:"issuer"`
	ClientID          string            `mapstructure:"client_id"`
	ClientSecret      string            `mapstructure:"client_secret"`
	Scopes            []string          `mapstructure:"scopes"`
	DeviceEndpoint    string            `mapstructure:"device_endpoint"`
	TokenEndpoint     string            `mapstructure:"token_endpoint"`
	UserInfoEndpoint  string            `mapstructure:"userinfo_endpoint"`
	JWKSUri           string            `mapstructure:"jwks_uri"`
	SkipDiscovery     bool              `mapstructure:"skip_discovery"`
	CustomEndpoints   map[string]string `mapstructure:"custom_endpoints"`
	UserMapping       UserMapping       `mapstructure:"user_mapping"`
	ResearchPolicies  ResearchPolicies  `mapstructure:"research_policies"`
	Priority          int               `mapstructure:"priority"`
	UserType          string            `mapstructure:"user_type"`
	EnabledForLogin   bool              `mapstructure:"enabled_for_login"`
	VerificationOnly  bool              `mapstructure:"verification_only"`
	RequirePKCE       bool              `mapstructure:"require_pkce"`
	AllowMissingNonce bool              `mapstructure:"allow_missing_nonce"`
}

// UserMapping defines how to map OIDC claims to user attributes
type UserMapping struct {
	UsernameClaim       string            `mapstructure:"username_claim"`
	EmailClaim          string            `mapstructure:"email_claim"`
	NameClaim           string            `mapstructure:"name_claim"`
	GroupsClaim         string            `mapstructure:"groups_claim"`
	RolesClaim          string            `mapstructure:"roles_claim"`
	DepartmentClaim     string            `mapstructure:"department_claim"`
	OrganizationClaim   string            `mapstructure:"organization_claim"`
	InstitutionClaim    string            `mapstructure:"institution_claim"`
	OrcidClaim          string            `mapstructure:"orcid_claim"`
	UsernameTemplate    string            `mapstructure:"username_template"`
	DisplayNameTemplate string            `mapstructure:"display_name_template"`
	GroupPrefix         string            `mapstructure:"group_prefix"`
	GroupMappings       map[string]string `mapstructure:"group_mappings"`
	AllowedGroups       []string          `mapstructure:"allowed_groups"`
	AllowedRoles        []string          `mapstructure:"allowed_roles"`
}

// ResearchPolicies contains research computing specific policies
type ResearchPolicies struct {
	EnableProjectGroups           bool `mapstructure:"enable_project_groups"`
	EnableInstitutionalValidation bool `mapstructure:"enable_institutional_validation"`
	EnableAllocationChecking      bool `mapstructure:"enable_allocation_checking"`
	EnableDataUseAgreements       bool `mapstructure:"enable_data_use_agreements"`
}

// LocationHistoryConfig controls how per-user login location history is stored
// for the "unusual location" risk-score signal.
type LocationHistoryConfig struct {
	// HistoryWindow is how far back recorded locations are considered "known".
	// Entries older than this are ignored during checks and pruned on write.
	// Defaults to 90 days when zero.
	HistoryWindow time.Duration `mapstructure:"history_window"`

	// MaxLocationsPerUser caps the number of location entries kept per user.
	// When the cap is hit the oldest entry is evicted.  Defaults to 10.
	MaxLocationsPerUser int `mapstructure:"max_locations_per_user"`

	// PersistPath is an optional file path where the location history is
	// saved as JSON so it survives broker restarts.  Leave empty to use
	// an in-memory-only store.
	PersistPath string `mapstructure:"persist_path"`
}

// AuthenticationConfig contains authentication policies
type AuthenticationConfig struct {
	TokenLifetime         time.Duration                   `mapstructure:"token_lifetime"`
	RefreshThreshold      time.Duration                   `mapstructure:"refresh_threshold"`
	MaxConcurrentSessions int                             `mapstructure:"max_concurrent_sessions"`
	IdleTimeout           time.Duration                   `mapstructure:"idle_timeout"`
	RequireGroups         []string                        `mapstructure:"require_groups"`
	Policies              map[string]AuthenticationPolicy `mapstructure:"policies"`
	NetworkRequirements   NetworkRequirements             `mapstructure:"network_requirements"`
	TimeBasedPolicies     TimeBasedPolicies               `mapstructure:"time_based_policies"`
	RiskPolicies          []RiskPolicy                    `mapstructure:"risk_policies"`
	GeoIPDatabasePath     string                          `mapstructure:"geoip_database_path"`
	LocationHistory       LocationHistoryConfig           `mapstructure:"location_history"`
}

// AuthenticationPolicy defines access control policies
type AuthenticationPolicy struct {
	RequireGroups                   []string      `mapstructure:"require_groups"`
	RequireDeviceTrust              bool          `mapstructure:"require_device_trust"`
	MaxSessionDuration              time.Duration `mapstructure:"max_session_duration"`
	RequireReauthForNewHosts        bool          `mapstructure:"require_reauth_for_new_hosts"`
	RequireInstitutionalAffiliation bool          `mapstructure:"require_institutional_affiliation"`
	RequireAllocationVerification   bool          `mapstructure:"require_allocation_verification"`
	RequireProjectMembership        string        `mapstructure:"require_project_membership"`
	AuditLevel                      string        `mapstructure:"audit_level"`
	AllowUnstrustedDevices          bool          `mapstructure:"allow_untrusted_devices"`
	RequireAdditionalMFA            bool          `mapstructure:"require_additional_mfa"`
	NoDataExport                    bool          `mapstructure:"no_data_export"`
	SessionRecording                bool          `mapstructure:"session_recording"`
	RequireApprovalFor              []string      `mapstructure:"require_approval_for"`
	IPWhitelist                     []string      `mapstructure:"ip_whitelist"`
}

// NetworkRequirements defines network-level requirements
type NetworkRequirements struct {
	RequireTailscale      bool   `mapstructure:"require_tailscale"`
	TailscaleAPIKey       string `mapstructure:"tailscale_api_key"`
	ValidateDeviceTrust   bool   `mapstructure:"validate_device_trust"`
	RequirePrivateNetwork bool   `mapstructure:"require_private_network"`
}

// TimeBasedPolicies defines time-based access controls
type TimeBasedPolicies struct {
	AcademicCalendar AcademicCalendar  `mapstructure:"academic_calendar"`
	ResearchSchedule ResearchSchedule  `mapstructure:"research_schedule"`
	TimeRestrictions []TimeRestriction `mapstructure:"time_restrictions"`
	GeoRestrictions  []GeoRestriction  `mapstructure:"geo_restrictions"`
}

// AcademicCalendar defines academic calendar periods
type AcademicCalendar struct {
	FallSemester   string `mapstructure:"fall_semester"`
	SpringSemester string `mapstructure:"spring_semester"`
	SummerSession  string `mapstructure:"summer_session"`
}

// ResearchSchedule defines research computing schedule
type ResearchSchedule struct {
	MaintenanceWindows  []string `mapstructure:"maintenance_windows"`
	HolidayRestrictions []string `mapstructure:"holiday_restrictions"`
}

// TimeRestriction defines time-based access restrictions
type TimeRestriction struct {
	Providers    []string `mapstructure:"providers"`
	AllowedHours string   `mapstructure:"allowed_hours"`
	Timezone     string   `mapstructure:"timezone"`
	Exceptions   []string `mapstructure:"exceptions"`
}

// GeoRestriction defines geographic access restrictions
type GeoRestriction struct {
	Providers        []string `mapstructure:"providers"`
	AllowedCountries []string `mapstructure:"allowed_countries"`
	BlockedCountries []string `mapstructure:"blocked_countries"`
}

// RiskPolicy defines risk-based access policies
type RiskPolicy struct {
	Condition      string `mapstructure:"condition"`
	Action         string `mapstructure:"action"`
	Recommendation string `mapstructure:"recommendation"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	TokenEncryptionKey string          `mapstructure:"token_encryption_key"`
	AuditEnabled       bool            `mapstructure:"audit_enabled"`
	SecureTokenStorage bool            `mapstructure:"secure_token_storage"`
	TLSVerification    TLSVerification `mapstructure:"tls_verification"`
	RateLimiting       RateLimiting    `mapstructure:"rate_limiting"`
	RequirePKCE        bool            `mapstructure:"require_pkce"`
	VerifyAudience     bool            `mapstructure:"verify_audience"`
	RequireAuthTime    bool            `mapstructure:"require_auth_time"`
	MaxTokenAge        time.Duration   `mapstructure:"max_token_age"`
	ClockSkewTolerance time.Duration   `mapstructure:"clock_skew_tolerance"`
}

// TLSVerification contains TLS verification settings
type TLSVerification struct {
	// PinnedCertificates is a list of SHA-256 fingerprints (lowercase hex,
	// with or without colon separators) of certificates that must appear in
	// the server's TLS chain. When non-empty, connections whose chain does
	// not contain a matching certificate are rejected.
	PinnedCertificates []string `mapstructure:"pinned_certificates"`
	// TrustedCABundle is the path to a PEM file containing one or more CA
	// certificates that replace the system trust store for OIDC provider
	// connections. Leave empty to use the system store.
	TrustedCABundle string `mapstructure:"trusted_ca_bundle"`
	// SkipTLSVerify disables TLS certificate verification. This is insecure
	// and is only permitted when the OIDC_AUTH_DEV environment variable is
	// set. A loud warning is logged whenever this setting is active.
	SkipTLSVerify bool `mapstructure:"skip_tls_verify"`
}

// RateLimiting contains rate limiting settings
type RateLimiting struct {
	MaxRequestsPerMinute int `mapstructure:"max_requests_per_minute"`
	MaxConcurrentAuths   int `mapstructure:"max_concurrent_auths"`
}

// CloudConfig contains cloud provider integration settings
type CloudConfig struct {
	Provider        string      `mapstructure:"provider"`
	AutoDiscovery   bool        `mapstructure:"auto_discovery"`
	Sources         []string    `mapstructure:"sources"`
	AWS             AWSConfig   `mapstructure:"aws"`
	Azure           AzureConfig `mapstructure:"azure"`
	GCP             GCPConfig   `mapstructure:"gcp"`
	MetadataSources []string    `mapstructure:"metadata_sources"`
}

// AWSConfig contains AWS-specific configuration
type AWSConfig struct {
	Region         string                  `mapstructure:"region"`
	ParameterStore AWSParameterStoreConfig `mapstructure:"parameter_store"`
}

// AWSParameterStoreConfig contains AWS Parameter Store settings
type AWSParameterStoreConfig struct {
	Prefix     string            `mapstructure:"prefix"`
	Parameters map[string]string `mapstructure:"parameters"`
}

// AzureConfig contains Azure-specific configuration
type AzureConfig struct {
	KeyVault AzureKeyVaultConfig `mapstructure:"key_vault"`
}

// AzureKeyVaultConfig contains Azure Key Vault settings
type AzureKeyVaultConfig struct {
	VaultName string            `mapstructure:"vault_name"`
	Secrets   map[string]string `mapstructure:"secrets"`
}

// GCPConfig contains GCP-specific configuration
type GCPConfig struct {
	ProjectID     string                 `mapstructure:"project_id"`
	SecretManager GCPSecretManagerConfig `mapstructure:"secret_manager"`
}

// GCPSecretManagerConfig contains GCP Secret Manager settings
type GCPSecretManagerConfig struct {
	Secrets map[string]string `mapstructure:"secrets"`
}

// AuditConfig contains audit logging configuration
type AuditConfig struct {
	Enabled                  bool          `mapstructure:"enabled"`
	Format                   string        `mapstructure:"format"`
	Outputs                  []AuditOutput `mapstructure:"outputs"`
	Events                   []string      `mapstructure:"events"`
	IncludeTailscaleMetadata bool          `mapstructure:"include_tailscale_metadata"`
	IncludeDeviceFingerprint bool          `mapstructure:"include_device_fingerprint"`
	IncludeNetworkPath       bool          `mapstructure:"include_network_path"`
	ComplianceFrameworks     []string      `mapstructure:"compliance_frameworks"`
	RetentionPeriod          string        `mapstructure:"retention_period"`
	// BufferSize is the capacity of the in-memory audit event channel.
	// Defaults to 1000 when ≤ 0.
	BufferSize int `mapstructure:"buffer_size"`
	// OverflowStrategy controls what happens when the event buffer is full.
	// Valid values:
	//   "drop"  – discard the event and increment the dropped counter (default)
	//   "block" – block the caller until buffer space is available (backpressure)
	//   "sync"  – bypass the channel and write the event synchronously
	OverflowStrategy string `mapstructure:"overflow_strategy"`
}

// AuditOutput defines where audit logs are sent
type AuditOutput struct {
	Type     string            `mapstructure:"type"`
	Path     string            `mapstructure:"path"`
	URL      string            `mapstructure:"url"`
	Headers  map[string]string `mapstructure:"headers"`
	Facility string            `mapstructure:"facility"`
	Severity string            `mapstructure:"severity"`
	Rotation string            `mapstructure:"rotation"`
}

// LoadConfig loads configuration from file
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Set config file path
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	// Enable environment variable support for safe settings only
	v.SetEnvPrefix("OIDC_AUTH")
	bindSafeEnvironmentVariables(v)

	// Check config file permissions
	if info, err := os.Stat(configPath); err == nil {
		if mode := info.Mode().Perm(); mode&0137 != 0 {
			log.Printf("WARNING: config file %s has permissions %04o, which are more permissive than recommended 0640", configPath, mode)
		}
	}

	// Try to read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, use defaults and environment variables
			return loadFromEnvironment(v)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := resolveSecretReferences(&config); err != nil {
		return nil, fmt.Errorf("failed to resolve secret references: %w", err)
	}

	if err := validateSecurityConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// loadFromEnvironment loads configuration from environment variables
func loadFromEnvironment(v *viper.Viper) (*Config, error) {
	var config Config

	// Load from environment variables
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config from environment: %w", err)
	}

	if err := resolveSecretReferences(&config); err != nil {
		return nil, fmt.Errorf("failed to resolve secret references: %w", err)
	}

	// Check for required environment variables
	if providerURL := os.Getenv("OIDC_PROVIDER_URL"); providerURL != "" {
		clientID := os.Getenv("OIDC_CLIENT_ID")
		if clientID == "" {
			return nil, fmt.Errorf("OIDC_CLIENT_ID environment variable required when OIDC_PROVIDER_URL is set")
		}

		// Create minimal provider configuration
		config.OIDC.Providers = []OIDCProvider{
			{
				Name:     "default",
				Issuer:   providerURL,
				ClientID: clientID,
				Scopes:   []string{"openid", "email", "profile"},
				UserMapping: UserMapping{
					UsernameClaim: "email",
					EmailClaim:    "email",
					NameClaim:     "name",
					GroupsClaim:   "groups",
				},
				EnabledForLogin: true,
			},
		}
	}

	if err := validateSecurityConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.socket_path", "/var/run/oidc-auth/broker.sock")
	v.SetDefault("server.log_level", "info")
	v.SetDefault("server.audit_log", "/var/log/oidc-auth/audit.log")
	v.SetDefault("server.socket_mode", 0660)
	v.SetDefault("server.socket_group", "")
	v.SetDefault("server.require_peer_auth", true)
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")

	// Authentication defaults
	v.SetDefault("authentication.token_lifetime", "8h")
	v.SetDefault("authentication.refresh_threshold", "1h")
	v.SetDefault("authentication.max_concurrent_sessions", 10)

	// Security defaults
	v.SetDefault("security.audit_enabled", true)
	v.SetDefault("security.secure_token_storage", true)
	v.SetDefault("security.require_pkce", true)
	v.SetDefault("security.verify_audience", true)
	v.SetDefault("security.require_auth_time", false)
	v.SetDefault("security.max_token_age", "24h")
	v.SetDefault("security.clock_skew_tolerance", "5m")

	// Cloud defaults
	v.SetDefault("cloud.auto_discovery", true)
	v.SetDefault("cloud.metadata_sources", []string{"aws", "azure", "gcp"})

	// Audit defaults
	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.format", "json")
	v.SetDefault("audit.events", []string{
		"authentication_attempts",
		"authorization_decisions",
		"token_validation",
		"configuration_changes",
	})
	v.SetDefault("audit.retention_period", "7_years")
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.SocketPath == "" {
		return fmt.Errorf("server.socket_path is required")
	}

	// Validate OIDC providers
	if len(c.OIDC.Providers) == 0 {
		return fmt.Errorf("at least one OIDC provider must be configured")
	}

	for i, provider := range c.OIDC.Providers {
		if provider.Name == "" {
			return fmt.Errorf("provider[%d].name is required", i)
		}
		if provider.Issuer == "" {
			return fmt.Errorf("provider[%d].issuer is required", i)
		}
		// Endpoints must be HTTPS so tokens and codes are never sent in clear.
		// http:// (and localhost) is permitted only in development mode.
		for label, endpoint := range map[string]string{
			"issuer":            provider.Issuer,
			"device_endpoint":   provider.DeviceEndpoint,
			"token_endpoint":    provider.TokenEndpoint,
			"userinfo_endpoint": provider.UserInfoEndpoint,
			"jwks_uri":          provider.JWKSUri,
		} {
			if err := validateHTTPSEndpoint(endpoint); err != nil {
				return fmt.Errorf("provider[%d].%s: %w", i, label, err)
			}
		}
		if provider.ClientID == "" {
			return fmt.Errorf("provider[%d].client_id is required", i)
		}
		if len(provider.Scopes) == 0 {
			return fmt.Errorf("provider[%d].scopes is required", i)
		}

		// Validate required scopes
		hasOpenID := false
		for _, scope := range provider.Scopes {
			if scope == "openid" {
				hasOpenID = true
				break
			}
		}
		if !hasOpenID {
			return fmt.Errorf("provider[%d].scopes must include 'openid'", i)
		}
	}

	// Validate authentication configuration
	if c.Authentication.TokenLifetime <= 0 {
		return fmt.Errorf("authentication.token_lifetime must be positive")
	}
	if c.Authentication.RefreshThreshold <= 0 {
		return fmt.Errorf("authentication.refresh_threshold must be positive")
	}
	if c.Authentication.MaxConcurrentSessions <= 0 {
		return fmt.Errorf("authentication.max_concurrent_sessions must be positive")
	}
	if c.Authentication.RefreshThreshold >= c.Authentication.TokenLifetime {
		return fmt.Errorf("authentication.refresh_threshold (%v) must be less than token_lifetime (%v)",
			c.Authentication.RefreshThreshold, c.Authentication.TokenLifetime)
	}

	return nil
}

// validateHTTPSEndpoint ensures a configured OIDC endpoint URL uses HTTPS.
// Empty values are allowed (the field is optional). In development mode
// (OIDC_AUTH_DEV) http:// and localhost are tolerated to ease local testing.
func validateHTTPSEndpoint(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if isDevelopmentMode() {
		return nil
	}
	return fmt.Errorf("must use https (got %q); set OIDC_AUTH_DEV=true to override for development", u.Scheme)
}

// isDevelopmentMode checks if development mode is enabled via OIDC_AUTH_DEV environment variable.
func isDevelopmentMode() bool {
	val := strings.ToLower(os.Getenv("OIDC_AUTH_DEV"))
	return val == "true" || val == "1" || val == "yes"
}

// bindSafeEnvironmentVariables binds only non-security-critical config keys to environment variables.
// Security booleans (secure_token_storage, verify_audience, require_pkce, skip_tls_verify) are NOT
// bound in production mode — they can only come from the config file or defaults.
func bindSafeEnvironmentVariables(v *viper.Viper) {
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Server settings (safe)
	safeKeys := []string{
		"server.socket_path",
		"server.log_level",
		"server.audit_log",
		"server.socket_group",
		"server.read_timeout",
		"server.write_timeout",

		// Authentication settings (safe)
		"authentication.token_lifetime",
		"authentication.refresh_threshold",
		"authentication.max_concurrent_sessions",

		// Cloud settings (safe)
		"cloud.provider",
		"cloud.auto_discovery",

		// Audit settings (safe)
		"audit.format",
		"audit.retention_period",

		// Security settings (safe subset)
		"security.token_encryption_key",
		"security.rate_limiting.max_requests_per_minute",
		"security.rate_limiting.max_concurrent_auths",
	}

	for _, key := range safeKeys {
		_ = v.BindEnv(key)
	}

	// In development mode, also bind security-critical settings with a warning
	if isDevelopmentMode() {
		log.Printf("WARNING: Development mode enabled (OIDC_AUTH_DEV=true). Security settings can be overridden via environment variables. DO NOT use in production.")

		securityKeys := []string{
			"security.secure_token_storage",
			"security.verify_audience",
			"security.require_pkce",
			"security.tls_verification.skip_tls_verify",
		}

		for _, key := range securityKeys {
			_ = v.BindEnv(key)
		}
	}
}

// validateSecurityConfig validates that security-critical settings are not weakened.
// In development mode, weakened settings produce warnings instead of errors.
func validateSecurityConfig(cfg *Config) error {
	devMode := isDevelopmentMode()

	if !cfg.Security.SecureTokenStorage {
		if devMode {
			log.Printf("WARNING: secure_token_storage is disabled (development mode)")
		} else {
			return fmt.Errorf("security.secure_token_storage must be enabled; set OIDC_AUTH_DEV=true to override for development")
		}
	}

	if !cfg.Security.VerifyAudience {
		if devMode {
			log.Printf("WARNING: verify_audience is disabled (development mode)")
		} else {
			return fmt.Errorf("security.verify_audience must be enabled; set OIDC_AUTH_DEV=true to override for development")
		}
	}

	if !cfg.Security.RequirePKCE {
		if devMode {
			log.Printf("WARNING: require_pkce is disabled (development mode)")
		} else {
			return fmt.Errorf("security.require_pkce must be enabled; set OIDC_AUTH_DEV=true to override for development")
		}
	}

	if cfg.Security.TLSVerification.SkipTLSVerify {
		if devMode {
			log.Printf("WARNING: skip_tls_verify is enabled (development mode)")
		} else {
			return fmt.Errorf("security.tls_verification.skip_tls_verify must be disabled; set OIDC_AUTH_DEV=true to override for development")
		}
	}

	return nil
}

// resolveSecretReferences resolves secret values that use reference prefixes:
//   - "env:VAR_NAME" reads the value from the named environment variable
//   - "file:/path/to/secret" reads the value from a file (whitespace-trimmed)
//   - Plain values are passed through unchanged
func resolveSecretReferences(cfg *Config) error {
	// Resolve provider client secrets
	for i := range cfg.OIDC.Providers {
		resolved, err := resolveSecretValue(cfg.OIDC.Providers[i].ClientSecret)
		if err != nil {
			return fmt.Errorf("provider %q client_secret: %w", cfg.OIDC.Providers[i].Name, err)
		}
		cfg.OIDC.Providers[i].ClientSecret = resolved
	}

	// Resolve token encryption key
	resolved, err := resolveSecretValue(cfg.Security.TokenEncryptionKey)
	if err != nil {
		return fmt.Errorf("security.token_encryption_key: %w", err)
	}
	cfg.Security.TokenEncryptionKey = resolved

	return nil
}

// resolveSecretValue resolves a single secret value. It returns the value
// unchanged if it does not carry a recognized prefix.
func resolveSecretValue(value string) (string, error) {
	if value == "" {
		return value, nil
	}

	if strings.HasPrefix(value, "env:") {
		envVar := strings.TrimPrefix(value, "env:")
		envVal := os.Getenv(envVar)
		if envVal == "" {
			return "", fmt.Errorf("environment variable %q is not set or empty", envVar)
		}
		return envVal, nil
	}

	if strings.HasPrefix(value, "file:") {
		filePath := strings.TrimPrefix(value, "file:")
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read secret file %q: %w", filePath, err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	return value, nil
}
