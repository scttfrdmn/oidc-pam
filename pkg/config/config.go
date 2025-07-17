package config

import (
	"fmt"
	"os"
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
	SocketPath   string        `mapstructure:"socket_path"`
	LogLevel     string        `mapstructure:"log_level"`
	AuditLog     string        `mapstructure:"audit_log"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// OIDCConfig contains OIDC provider configuration
type OIDCConfig struct {
	Providers []OIDCProvider `mapstructure:"providers"`
}

// OIDCProvider represents a single OIDC provider configuration
type OIDCProvider struct {
	Name                string            `mapstructure:"name"`
	Issuer              string            `mapstructure:"issuer"`
	ClientID            string            `mapstructure:"client_id"`
	Scopes              []string          `mapstructure:"scopes"`
	DeviceEndpoint      string            `mapstructure:"device_endpoint"`
	TokenEndpoint       string            `mapstructure:"token_endpoint"`
	UserInfoEndpoint    string            `mapstructure:"userinfo_endpoint"`
	CustomEndpoints     map[string]string `mapstructure:"custom_endpoints"`
	UserMapping         UserMapping       `mapstructure:"user_mapping"`
	ResearchPolicies    ResearchPolicies  `mapstructure:"research_policies"`
	Priority            int               `mapstructure:"priority"`
	UserType            string            `mapstructure:"user_type"`
	EnabledForLogin     bool              `mapstructure:"enabled_for_login"`
	VerificationOnly    bool              `mapstructure:"verification_only"`
}

// UserMapping defines how to map OIDC claims to user attributes
type UserMapping struct {
	UsernameClaim      string `mapstructure:"username_claim"`
	EmailClaim         string `mapstructure:"email_claim"`
	NameClaim          string `mapstructure:"name_claim"`
	GroupsClaim        string `mapstructure:"groups_claim"`
	RolesClaim         string `mapstructure:"roles_claim"`
	DepartmentClaim    string `mapstructure:"department_claim"`
	OrganizationClaim  string `mapstructure:"organization_claim"`
	InstitutionClaim   string `mapstructure:"institution_claim"`
	OrcidClaim         string `mapstructure:"orcid_claim"`
	UsernameTemplate   string `mapstructure:"username_template"`
	DisplayNameTemplate string `mapstructure:"display_name_template"`
	GroupPrefix        string `mapstructure:"group_prefix"`
	GroupMappings      map[string]string `mapstructure:"group_mappings"`
}

// ResearchPolicies contains research computing specific policies
type ResearchPolicies struct {
	EnableProjectGroups         bool `mapstructure:"enable_project_groups"`
	EnableInstitutionalValidation bool `mapstructure:"enable_institutional_validation"`
	EnableAllocationChecking    bool `mapstructure:"enable_allocation_checking"`
	EnableDataUseAgreements     bool `mapstructure:"enable_data_use_agreements"`
}

// AuthenticationConfig contains authentication policies
type AuthenticationConfig struct {
	TokenLifetime         time.Duration                  `mapstructure:"token_lifetime"`
	RefreshThreshold      time.Duration                  `mapstructure:"refresh_threshold"`
	MaxConcurrentSessions int                            `mapstructure:"max_concurrent_sessions"`
	RequireGroups         []string                       `mapstructure:"require_groups"`
	Policies              map[string]AuthenticationPolicy `mapstructure:"policies"`
	NetworkRequirements   NetworkRequirements            `mapstructure:"network_requirements"`
	TimeBasedPolicies     TimeBasedPolicies             `mapstructure:"time_based_policies"`
	RiskPolicies          []RiskPolicy                   `mapstructure:"risk_policies"`
}

// AuthenticationPolicy defines access control policies
type AuthenticationPolicy struct {
	RequireGroups                 []string      `mapstructure:"require_groups"`
	RequireDeviceTrust            bool          `mapstructure:"require_device_trust"`
	MaxSessionDuration            time.Duration `mapstructure:"max_session_duration"`
	RequireReauthForNewHosts      bool          `mapstructure:"require_reauth_for_new_hosts"`
	RequireInstitutionalAffiliation bool         `mapstructure:"require_institutional_affiliation"`
	RequireAllocationVerification bool          `mapstructure:"require_allocation_verification"`
	RequireProjectMembership      string        `mapstructure:"require_project_membership"`
	AuditLevel                    string        `mapstructure:"audit_level"`
	AllowUnstrustedDevices        bool          `mapstructure:"allow_untrusted_devices"`
	RequireAdditionalMFA          bool          `mapstructure:"require_additional_mfa"`
	NoDataExport                  bool          `mapstructure:"no_data_export"`
	SessionRecording              bool          `mapstructure:"session_recording"`
	RequireApprovalFor            []string      `mapstructure:"require_approval_for"`
	IPWhitelist                   []string      `mapstructure:"ip_whitelist"`
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
	AcademicCalendar    AcademicCalendar    `mapstructure:"academic_calendar"`
	ResearchSchedule    ResearchSchedule    `mapstructure:"research_schedule"`
	TimeRestrictions    []TimeRestriction   `mapstructure:"time_restrictions"`
	GeoRestrictions     []GeoRestriction    `mapstructure:"geo_restrictions"`
}

// AcademicCalendar defines academic calendar periods
type AcademicCalendar struct {
	FallSemester   string `mapstructure:"fall_semester"`
	SpringSemester string `mapstructure:"spring_semester"`
	SummerSession  string `mapstructure:"summer_session"`
}

// ResearchSchedule defines research computing schedule
type ResearchSchedule struct {
	MaintenanceWindows    []string `mapstructure:"maintenance_windows"`
	HolidayRestrictions   []string `mapstructure:"holiday_restrictions"`
}

// TimeRestriction defines time-based access restrictions
type TimeRestriction struct {
	Providers     []string `mapstructure:"providers"`
	AllowedHours  string   `mapstructure:"allowed_hours"`
	Timezone      string   `mapstructure:"timezone"`
	Exceptions    []string `mapstructure:"exceptions"`
}

// GeoRestriction defines geographic access restrictions
type GeoRestriction struct {
	Providers         []string `mapstructure:"providers"`
	AllowedCountries  []string `mapstructure:"allowed_countries"`
	BlockedCountries  []string `mapstructure:"blocked_countries"`
}

// RiskPolicy defines risk-based access policies
type RiskPolicy struct {
	Condition      string `mapstructure:"condition"`
	Action         string `mapstructure:"action"`
	Recommendation string `mapstructure:"recommendation"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	TokenEncryptionKey      string        `mapstructure:"token_encryption_key"`
	AuditEnabled            bool          `mapstructure:"audit_enabled"`
	SecureTokenStorage      bool          `mapstructure:"secure_token_storage"`
	TLSVerification         TLSVerification `mapstructure:"tls_verification"`
	RateLimiting            RateLimiting    `mapstructure:"rate_limiting"`
	RequirePKCE             bool          `mapstructure:"require_pkce"`
	VerifyAudience          bool          `mapstructure:"verify_audience"`
	RequireAuthTime         bool          `mapstructure:"require_auth_time"`
	MaxTokenAge             time.Duration `mapstructure:"max_token_age"`
	ClockSkewTolerance      time.Duration `mapstructure:"clock_skew_tolerance"`
}

// TLSVerification contains TLS verification settings
type TLSVerification struct {
	PinCertificates   bool   `mapstructure:"pin_certificates"`
	TrustedCABundle   string `mapstructure:"trusted_ca_bundle"`
	SkipTLSVerify     bool   `mapstructure:"skip_tls_verify"`
}

// RateLimiting contains rate limiting settings
type RateLimiting struct {
	MaxRequestsPerMinute int `mapstructure:"max_requests_per_minute"`
	MaxConcurrentAuths   int `mapstructure:"max_concurrent_auths"`
}

// CloudConfig contains cloud provider integration settings
type CloudConfig struct {
	Provider       string                    `mapstructure:"provider"`
	AutoDiscovery  bool                      `mapstructure:"auto_discovery"`
	Sources        []string                  `mapstructure:"sources"`
	AWS            AWSConfig                 `mapstructure:"aws"`
	Azure          AzureConfig               `mapstructure:"azure"`
	GCP            GCPConfig                 `mapstructure:"gcp"`
	MetadataSources []string                  `mapstructure:"metadata_sources"`
}

// AWSConfig contains AWS-specific configuration
type AWSConfig struct {
	Region         string                    `mapstructure:"region"`
	ParameterStore AWSParameterStoreConfig   `mapstructure:"parameter_store"`
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
	ProjectID     string                   `mapstructure:"project_id"`
	SecretManager GCPSecretManagerConfig   `mapstructure:"secret_manager"`
}

// GCPSecretManagerConfig contains GCP Secret Manager settings
type GCPSecretManagerConfig struct {
	Secrets map[string]string `mapstructure:"secrets"`
}

// AuditConfig contains audit logging configuration
type AuditConfig struct {
	Enabled                     bool             `mapstructure:"enabled"`
	Format                      string           `mapstructure:"format"`
	Outputs                     []AuditOutput    `mapstructure:"outputs"`
	Events                      []string         `mapstructure:"events"`
	IncludeTailscaleMetadata    bool             `mapstructure:"include_tailscale_metadata"`
	IncludeDeviceFingerprint    bool             `mapstructure:"include_device_fingerprint"`
	IncludeNetworkPath          bool             `mapstructure:"include_network_path"`
	ComplianceFrameworks        []string         `mapstructure:"compliance_frameworks"`
	RetentionPeriod             string           `mapstructure:"retention_period"`
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
	
	// Enable environment variable support
	v.SetEnvPrefix("OIDC_AUTH")
	v.AutomaticEnv()
	
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
	
	return &config, nil
}

// loadFromEnvironment loads configuration from environment variables
func loadFromEnvironment(v *viper.Viper) (*Config, error) {
	var config Config
	
	// Load from environment variables
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config from environment: %w", err)
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
	
	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.socket_path", "/var/run/oidc-auth/broker.sock")
	v.SetDefault("server.log_level", "info")
	v.SetDefault("server.audit_log", "/var/log/oidc-auth/audit.log")
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
	
	return nil
}