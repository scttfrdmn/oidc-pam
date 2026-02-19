package auth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"golang.org/x/oauth2"
)

// DeviceFlow represents an OAuth2 device authorization flow
type DeviceFlow struct {
	DeviceCode      string
	UserCode        string
	DeviceURL       string
	ExpiresAt       time.Time
	PollingInterval int
	ClientID        string
	Scopes          []string
}

// DeviceAuthResponse represents the response from device authorization endpoint
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenResponse represents the response from token endpoint
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// OIDCProvider represents an OIDC provider with device flow support
type OIDCProvider struct {
	Name           string
	Config         OIDCProviderConfig
	Provider       *oidc.Provider
	Verifier       *oidc.IDTokenVerifier
	OAuth2Config   *oauth2.Config
	httpClient     *http.Client
	securityConfig config.SecurityConfig
}

// OIDCProviderConfig is an alias for the config type
type OIDCProviderConfig = config.OIDCProvider

// UserInfo represents user information from OIDC provider
type UserInfo struct {
	Subject       string
	Email         string
	Name          string
	Groups        []string
	Roles         []string
	Organization  string
	Institution   string
	Department    string
	ORCID         string
	DeviceTrusted bool
	Claims        map[string]interface{}
}

// Token represents an OAuth2/OIDC token
type Token struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresAt    time.Time
	Fingerprint  string
	Claims       map[string]interface{}
}

// NewOIDCProvider creates a new OIDC provider
func NewOIDCProvider(providerCfg OIDCProviderConfig, secCfg config.SecurityConfig) (*OIDCProvider, error) {
	// Build the TLS config first so both the discovery request and all
	// subsequent token/userinfo requests use the same TLS settings.
	tlsConfig, err := buildTLSConfig(secCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Pass the configured HTTP client to the OIDC provider discovery so that
	// the CA bundle, skip-verify flag, and certificate pins apply to the
	// /.well-known/openid-configuration fetch as well.
	ctx := oidc.ClientContext(context.Background(), httpClient)

	provider, err := oidc.NewProvider(ctx, providerCfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID:             providerCfg.ClientID,
		SkipClientIDCheck:    !secCfg.VerifyAudience,
		SupportedSigningAlgs: []string{"RS256", "ES256"},
	})

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:    providerCfg.ClientID,
		Endpoint:    provider.Endpoint(),
		Scopes:      providerCfg.Scopes,
		RedirectURL: "", // Not used for device flow
	}

	return &OIDCProvider{
		Name:           providerCfg.Name,
		Config:         providerCfg,
		Provider:       provider,
		Verifier:       verifier,
		OAuth2Config:   oauth2Config,
		httpClient:     httpClient,
		securityConfig: secCfg,
	}, nil
}

// buildTLSConfig constructs a *tls.Config from the security configuration.
// It always enforces TLS 1.2 as the minimum version and optionally applies:
//   - A custom CA bundle (TrustedCABundle) that replaces the system trust store
//   - InsecureSkipVerify (SkipTLSVerify) with a loud warning log
//   - Certificate pinning (PinnedCertificates) via VerifyPeerCertificate
func buildTLSConfig(secCfg config.SecurityConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load custom CA bundle if specified.
	if secCfg.TLSVerification.TrustedCABundle != "" {
		caPEM, err := os.ReadFile(secCfg.TLSVerification.TrustedCABundle)
		if err != nil {
			return nil, fmt.Errorf("failed to read trusted CA bundle %q: %w", secCfg.TLSVerification.TrustedCABundle, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid PEM certificates found in CA bundle %q", secCfg.TLSVerification.TrustedCABundle)
		}
		tlsCfg.RootCAs = pool
	}

	// Apply SkipTLSVerify — config.Validate() already blocks this outside dev
	// mode, so this path is only reached during testing or with OIDC_AUTH_DEV.
	if secCfg.TLSVerification.SkipTLSVerify {
		log.Warn().Msg("TLS certificate verification is DISABLED — this is insecure and must only be used for testing")
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // intentional, gated by config.Validate
	}

	// Apply certificate pinning.
	if len(secCfg.TLSVerification.PinnedCertificates) > 0 {
		// Normalise pins: lowercase hex without colons so both "aabbcc..."
		// and "aa:bb:cc:..." formats are accepted.
		pins := make(map[string]bool, len(secCfg.TLSVerification.PinnedCertificates))
		for _, pin := range secCfg.TLSVerification.PinnedCertificates {
			pins[strings.ToLower(strings.ReplaceAll(pin, ":", ""))] = true
		}

		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				fp := fmt.Sprintf("%x", sha256.Sum256(raw))
				if pins[fp] {
					return nil
				}
			}
			return fmt.Errorf("TLS certificate pinning: no certificate in the server chain matches a pinned fingerprint")
		}
	}

	return tlsCfg, nil
}

// StartDeviceFlow initiates the OAuth2 device authorization flow
func (p *OIDCProvider) StartDeviceFlow(req *AuthRequest) (*DeviceFlow, error) {
	// Get device authorization endpoint
	deviceEndpoint, err := p.getDeviceAuthorizationEndpoint()
	if err != nil {
		return nil, fmt.Errorf("failed to get device authorization endpoint: %w", err)
	}

	// Prepare request data
	data := url.Values{}
	data.Set("client_id", p.Config.ClientID)
	data.Set("scope", strings.Join(p.Config.Scopes, " "))

	// RFC 8628: Device flow is designed for public clients; do not send client_secret
	if p.Config.ClientSecret != "" {
		log.Warn().Str("provider", p.Name).Msg("Client secret configured but not sent for device flow (RFC 8628: device flow uses public clients)")
	}

	// Make request to device authorization endpoint
	resp, err := p.httpClient.PostForm(deviceEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("failed to request device authorization: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device authorization request failed with status %d", resp.StatusCode)
	}

	// Parse response
	var deviceResp DeviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		return nil, fmt.Errorf("failed to decode device authorization response: %w", err)
	}

	// Create device flow
	deviceFlow := &DeviceFlow{
		DeviceCode:      deviceResp.DeviceCode,
		UserCode:        deviceResp.UserCode,
		DeviceURL:       deviceResp.VerificationURI,
		ExpiresAt:       time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second),
		PollingInterval: deviceResp.Interval,
		ClientID:        p.Config.ClientID,
		Scopes:          p.Config.Scopes,
	}

	// Use complete URI if available (includes user code)
	if deviceResp.VerificationURIComplete != "" {
		deviceFlow.DeviceURL = deviceResp.VerificationURIComplete
	}

	log.Debug().
		Str("provider", p.Name).
		Str("device_code", deviceFlow.DeviceCode).
		Str("user_code", deviceFlow.UserCode).
		Str("device_url", deviceFlow.DeviceURL).
		Msg("Device flow initiated")

	return deviceFlow, nil
}

// PollDeviceAuthorization polls for device authorization completion.
// ctx is used for ID token verification so callers can apply deadlines.
func (p *OIDCProvider) PollDeviceAuthorization(ctx context.Context, deviceCode string) (*Token, error) {
	// Get token endpoint
	tokenEndpoint := p.Provider.Endpoint().TokenURL

	// Prepare request data
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCode)
	data.Set("client_id", p.Config.ClientID)

	// Make request to token endpoint
	resp, err := p.httpClient.PostForm(tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("failed to poll device authorization: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Parse response
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Handle error responses
	if tokenResp.Error != "" {
		return nil, fmt.Errorf("token error: %s", tokenResp.Error)
	}

	// Check if we have a valid response
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response")
	}

	// Parse and verify ID token if present
	var claims map[string]interface{}
	if tokenResp.IDToken != "" {
		idToken, err := p.Verifier.Verify(ctx, tokenResp.IDToken)
		if err != nil {
			return nil, fmt.Errorf("failed to verify ID token: %w", err)
		}

		if err := idToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
		}

		if err := p.validateIDTokenClaims(claims); err != nil {
			return nil, fmt.Errorf("ID token claim validation failed: %w", err)
		}
	}

	// Create token
	token := &Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Fingerprint:  p.generateTokenFingerprint(tokenResp.AccessToken),
		Claims:       claims,
	}

	log.Debug().
		Str("provider", p.Name).
		Str("token_type", token.TokenType).
		Time("expires_at", token.ExpiresAt).
		Msg("Device authorization completed")

	return token, nil
}

// GetUserInfo retrieves user information using the access token
func (p *OIDCProvider) GetUserInfo(token *Token) (*UserInfo, error) {
	// Get userinfo endpoint
	userInfoEndpoint := p.Provider.UserInfoEndpoint()
	if userInfoEndpoint == "" {
		// Fall back to ID token claims if no userinfo endpoint
		return p.extractUserInfoFromClaims(token.Claims)
	}

	// Create request to userinfo endpoint
	req, err := http.NewRequest("GET", userInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

	// Make request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	// Parse user info
	var userInfoClaims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfoClaims); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	// Merge with ID token claims if available
	if token.Claims != nil {
		for key, value := range token.Claims {
			if _, exists := userInfoClaims[key]; !exists {
				userInfoClaims[key] = value
			}
		}
	}

	return p.extractUserInfoFromClaims(userInfoClaims)
}

// RefreshToken exchanges a refresh token for a new access token (RFC 6749 §6).
// If the provider does not return a new refresh token, the original is preserved.
func (p *OIDCProvider) RefreshToken(ctx context.Context, refreshTokenStr string) (*Token, error) {
	if refreshTokenStr == "" {
		return nil, fmt.Errorf("refresh token is empty")
	}

	tokenEndpoint, err := p.tokenEndpointURL()
	if err != nil {
		return nil, fmt.Errorf("failed to get token endpoint: %w", err)
	}

	// Build refresh request body
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshTokenStr)
	data.Set("client_id", p.Config.ClientID)
	if len(p.Config.Scopes) > 0 {
		data.Set("scope", strings.Join(p.Config.Scopes, " "))
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token refresh request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token refresh response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("token refresh error: %s", tokenResp.Error)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token in refresh response")
	}

	// Verify the new ID token if the provider included one
	var claims map[string]interface{}
	if tokenResp.IDToken != "" && p.Verifier != nil {
		idToken, err := p.Verifier.Verify(ctx, tokenResp.IDToken)
		if err != nil {
			return nil, fmt.Errorf("failed to verify refreshed ID token: %w", err)
		}
		if err := idToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse refreshed ID token claims: %w", err)
		}
		if err := p.validateIDTokenClaims(claims); err != nil {
			return nil, fmt.Errorf("refreshed ID token claim validation failed: %w", err)
		}
	}

	// RFC 6749 §6: if the provider didn't issue a new refresh token, reuse the original.
	newRefreshToken := tokenResp.RefreshToken
	if newRefreshToken == "" {
		newRefreshToken = refreshTokenStr
	}

	token := &Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: newRefreshToken,
		IDToken:      tokenResp.IDToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Fingerprint:  p.generateTokenFingerprint(tokenResp.AccessToken),
		Claims:       claims,
	}

	log.Debug().
		Str("provider", p.Name).
		Time("expires_at", token.ExpiresAt).
		Msg("Token refreshed successfully")

	return token, nil
}

// tokenEndpointURL returns the OAuth2 token endpoint URL.
// It prefers the URL from OAuth2Config (set during OIDC discovery) and falls
// back to the live provider discovery if OAuth2Config is not populated.
func (p *OIDCProvider) tokenEndpointURL() (string, error) {
	if p.OAuth2Config != nil && p.OAuth2Config.Endpoint.TokenURL != "" {
		return p.OAuth2Config.Endpoint.TokenURL, nil
	}
	if p.Provider != nil {
		return p.Provider.Endpoint().TokenURL, nil
	}
	return "", fmt.Errorf("token endpoint not available: provider not initialized")
}

// validateIDTokenClaims performs post-verification claim validation
// checking auth_time presence and token age constraints.
func (p *OIDCProvider) validateIDTokenClaims(claims map[string]interface{}) error {
	// Check auth_time requirement
	authTimeVal, hasAuthTime := claims["auth_time"]
	if p.securityConfig.RequireAuthTime && !hasAuthTime {
		return fmt.Errorf("auth_time claim is required but not present in ID token")
	}

	// Check token age if MaxTokenAge is configured and auth_time is present
	if p.securityConfig.MaxTokenAge > 0 && hasAuthTime {
		var authTime time.Time
		switch v := authTimeVal.(type) {
		case float64:
			authTime = time.Unix(int64(v), 0)
		case json.Number:
			n, err := v.Int64()
			if err != nil {
				return fmt.Errorf("invalid auth_time value: %w", err)
			}
			authTime = time.Unix(n, 0)
		default:
			return fmt.Errorf("auth_time claim has unexpected type %T", authTimeVal)
		}

		maxAge := p.securityConfig.MaxTokenAge + p.securityConfig.ClockSkewTolerance
		if time.Since(authTime) > maxAge {
			return fmt.Errorf("token age exceeds maximum allowed age (%s)", p.securityConfig.MaxTokenAge)
		}

		log.Debug().
			Time("auth_time", authTime).
			Dur("token_age", time.Since(authTime)).
			Dur("max_token_age", p.securityConfig.MaxTokenAge).
			Msg("ID token age validated")
	}

	return nil
}

// Helper methods

func (p *OIDCProvider) getDeviceAuthorizationEndpoint() (string, error) {
	// Check if device endpoint is configured
	if p.Config.DeviceEndpoint != "" {
		return p.Config.DeviceEndpoint, nil
	}

	// Check custom endpoints
	if deviceEndpoint, ok := p.Config.CustomEndpoints["device_authorization"]; ok {
		return deviceEndpoint, nil
	}

	// Try to discover from provider metadata
	discoveryURL := p.Config.Issuer + "/.well-known/openid-configuration"

	resp, err := p.httpClient.Get(discoveryURL)
	if err != nil {
		// Fallback to common endpoint patterns
		return p.Config.Issuer + "/protocol/openid-connect/auth/device", nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Fallback to common endpoint patterns
		return p.Config.Issuer + "/protocol/openid-connect/auth/device", nil
	}

	var discoveryResp struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&discoveryResp); err != nil {
		// Fallback to common endpoint patterns
		return p.Config.Issuer + "/protocol/openid-connect/auth/device", nil
	}

	if discoveryResp.DeviceAuthorizationEndpoint != "" {
		return discoveryResp.DeviceAuthorizationEndpoint, nil
	}

	// Fallback to common endpoint patterns
	return p.Config.Issuer + "/protocol/openid-connect/auth/device", nil
}

func (p *OIDCProvider) generateTokenFingerprint(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return hex.EncodeToString(hash[:])
}

func (p *OIDCProvider) extractUserInfoFromClaims(claims map[string]interface{}) (*UserInfo, error) {
	mapping := p.Config.UserMapping

	userInfo := &UserInfo{
		Claims: claims,
	}

	// Extract subject
	if sub, ok := claims["sub"].(string); ok {
		userInfo.Subject = sub
	}

	// Extract email
	if mapping.EmailClaim != "" {
		if email, ok := claims[mapping.EmailClaim].(string); ok {
			userInfo.Email = email
		}
	}

	// Extract name
	if mapping.NameClaim != "" {
		if name, ok := claims[mapping.NameClaim].(string); ok {
			userInfo.Name = name
		}
	}

	// Extract groups
	if mapping.GroupsClaim != "" {
		if groups, ok := claims[mapping.GroupsClaim].([]interface{}); ok {
			for _, group := range groups {
				if groupStr, ok := group.(string); ok {
					// Apply group filtering if configured
					if mapping.GroupPrefix != "" {
						if strings.HasPrefix(groupStr, mapping.GroupPrefix) {
							groupStr = strings.TrimPrefix(groupStr, mapping.GroupPrefix)
						} else {
							continue // Skip groups that don't match prefix
						}
					}

					// Apply group mapping if configured
					if mapping.GroupMappings != nil {
						if mapped, ok := mapping.GroupMappings[groupStr]; ok {
							groupStr = mapped
						}
					}

					userInfo.Groups = append(userInfo.Groups, groupStr)
				}
			}
		}
	}

	// Extract roles
	if mapping.RolesClaim != "" {
		if roles, ok := claims[mapping.RolesClaim].([]interface{}); ok {
			for _, role := range roles {
				if roleStr, ok := role.(string); ok {
					userInfo.Roles = append(userInfo.Roles, roleStr)
				}
			}
		}
	}

	// Extract organization
	if mapping.OrganizationClaim != "" {
		if org, ok := claims[mapping.OrganizationClaim].(string); ok {
			userInfo.Organization = org
		}
	}

	// Extract institution
	if mapping.InstitutionClaim != "" {
		if inst, ok := claims[mapping.InstitutionClaim].(string); ok {
			userInfo.Institution = inst
		}
	}

	// Extract department
	if mapping.DepartmentClaim != "" {
		if dept, ok := claims[mapping.DepartmentClaim].(string); ok {
			userInfo.Department = dept
		}
	}

	// Extract ORCID
	if mapping.OrcidClaim != "" {
		if orcid, ok := claims[mapping.OrcidClaim].(string); ok {
			userInfo.ORCID = orcid
		}
	}

	// Set device trust (simplified implementation)
	// In a real implementation, this would check various factors
	if amr, ok := claims["amr"].([]interface{}); ok {
		for _, method := range amr {
			if methodStr, ok := method.(string); ok {
				if methodStr == "hwk" || methodStr == "fido" {
					userInfo.DeviceTrusted = true
					break
				}
			}
		}
	}

	log.Debug().
		Str("provider", p.Name).
		Str("subject", userInfo.Subject).
		Str("email", userInfo.Email).
		Str("name", userInfo.Name).
		Strs("groups", userInfo.Groups).
		Bool("device_trusted", userInfo.DeviceTrusted).
		Msg("Extracted user info from claims")

	return userInfo, nil
}
