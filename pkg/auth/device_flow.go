package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// OIDCProvider represents an OIDC provider with device flow support
type OIDCProvider struct {
	Name      string
	Config    OIDCProviderConfig
	Provider  *oidc.Provider
	Verifier  *oidc.IDTokenVerifier
	OAuth2Config *oauth2.Config
	httpClient *http.Client
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
func NewOIDCProvider(config OIDCProviderConfig) (*OIDCProvider, error) {
	ctx := context.Background()
	
	// Create OIDC provider
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.Scopes,
		RedirectURL:  "", // Not used for device flow
	}

	// Create HTTP client with appropriate timeout
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &OIDCProvider{
		Name:         config.Name,
		Config:       config,
		Provider:     provider,
		Verifier:     verifier,
		OAuth2Config: oauth2Config,
		httpClient:   httpClient,
	}, nil
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

	// Make request to device authorization endpoint
	resp, err := p.httpClient.PostForm(deviceEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("failed to request device authorization: %w", err)
	}
	defer resp.Body.Close()

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

// PollDeviceAuthorization polls for device authorization completion
func (p *OIDCProvider) PollDeviceAuthorization(deviceCode string) (*Token, error) {
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
	defer resp.Body.Close()

	// Parse response
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Handle error responses
	if tokenResp.Error != "" {
		return nil, fmt.Errorf(tokenResp.Error)
	}

	// Check if we have a valid response
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response")
	}

	// Parse and verify ID token if present
	var claims map[string]interface{}
	if tokenResp.IDToken != "" {
		idToken, err := p.Verifier.Verify(context.Background(), tokenResp.IDToken)
		if err != nil {
			return nil, fmt.Errorf("failed to verify ID token: %w", err)
		}
		
		if err := idToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
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
	defer resp.Body.Close()

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

// RefreshToken refreshes an access token
func (p *OIDCProvider) RefreshToken(tokenFingerprint string) (*Token, error) {
	// In a real implementation, this would look up the refresh token
	// associated with the fingerprint and use it to get a new access token
	return nil, fmt.Errorf("token refresh not implemented")
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
	// This is a simplified implementation - in reality, we would need to
	// query the provider's .well-known/openid-configuration endpoint
	// and look for the device_authorization_endpoint
	return p.Config.Issuer + "/oauth2/device", nil
}

func (p *OIDCProvider) generateTokenFingerprint(accessToken string) string {
	// Generate a simple fingerprint based on the first and last 8 characters
	// In a real implementation, this would be a proper hash
	if len(accessToken) < 16 {
		return accessToken
	}
	return accessToken[:8] + "..." + accessToken[len(accessToken)-8:]
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