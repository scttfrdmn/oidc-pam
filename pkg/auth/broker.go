package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
)

// Broker manages authentication requests and OIDC provider interactions
type Broker struct {
	config       *config.Config
	providers    map[string]*OIDCProvider
	tokenManager *TokenManager
	policyEngine *PolicyEngine
	auditLogger  *security.AuditLogger
	sessions     map[string]*Session
	sessionMutex sync.RWMutex
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

// Session represents an active authentication session
type Session struct {
	ID              string
	UserID          string
	Email           string
	Groups          []string
	Provider        string
	DeviceID        string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	LastAccessed    time.Time
	SourceIP        string
	UserAgent       string
	TokenFingerprint string
	SSHKeyID        string
	IsActive        bool
	RiskScore       int
	DeviceTrusted   bool
	Metadata        map[string]interface{}
}

// AuthRequest represents an authentication request
type AuthRequest struct {
	UserID       string
	SourceIP     string
	UserAgent    string
	TargetHost   string
	LoginType    string // "ssh", "console", "gui"
	DeviceID     string
	SessionID    string
	Timestamp    time.Time
	Metadata     map[string]interface{}
}

// AuthResponse represents the response to an authentication request
type AuthResponse struct {
	Success          bool
	UserID           string
	Email            string
	Groups           []string
	SessionID        string
	DeviceCode       string
	DeviceURL        string
	QRCode           string
	ExpiresAt        time.Time
	SSHPublicKey     string
	RequiresDevice   bool
	RequiresApproval bool
	ErrorCode        string
	ErrorMessage     string
	RiskScore        int
	Metadata         map[string]interface{}
}

// NewBroker creates a new authentication broker
func NewBroker(cfg *config.Config) (*Broker, error) {
	// Validate configuration
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}
	
	// Validate server configuration
	if cfg.Server.SocketPath == "" {
		return nil, fmt.Errorf("socket path cannot be empty")
	}
	
	// Validate OIDC configuration
	if len(cfg.OIDC.Providers) == 0 {
		return nil, fmt.Errorf("at least one OIDC provider must be configured")
	}
	
	// Validate security configuration
	if cfg.Security.TokenEncryptionKey == "" {
		return nil, fmt.Errorf("token encryption key is required for security")
	}
	
	if len(cfg.Security.TokenEncryptionKey) < 32 {
		return nil, fmt.Errorf("token encryption key must be at least 32 bytes for security")
	}
	
	// Validate OIDC provider security
	for _, provider := range cfg.OIDC.Providers {
		// Check for required openid scope
		hasOpenIDScope := false
		for _, scope := range provider.Scopes {
			if scope == "openid" {
				hasOpenIDScope = true
				break
			}
		}
		if !hasOpenIDScope {
			return nil, fmt.Errorf("provider '%s' must include 'openid' scope", provider.Name)
		}
		
		// Check for HTTPS requirement (except localhost for testing)
		if provider.Issuer != "" && !strings.HasPrefix(provider.Issuer, "https://") && 
		   !strings.HasPrefix(provider.Issuer, "http://localhost") &&
		   !strings.HasPrefix(provider.Issuer, "http://127.0.0.1") &&
		   !strings.HasPrefix(provider.Issuer, "mock://") {
			return nil, fmt.Errorf("provider '%s' issuer must use HTTPS for security", provider.Name)
		}
	}
	
	// Create token manager
	tokenManager, err := NewTokenManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create token manager: %w", err)
	}

	// Create policy engine
	policyEngine, err := NewPolicyEngine(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy engine: %w", err)
	}

	// Create audit logger
	auditLogger, err := security.NewAuditLogger(cfg.Audit)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Initialize OIDC providers
	providers := make(map[string]*OIDCProvider)
	for _, providerConfig := range cfg.OIDC.Providers {
		provider, err := NewOIDCProvider(providerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider '%s': %w", providerConfig.Name, err)
		}
		providers[providerConfig.Name] = provider
	}

	broker := &Broker{
		config:       cfg,
		providers:    providers,
		tokenManager: tokenManager,
		policyEngine: policyEngine,
		auditLogger:  auditLogger,
		sessions:     make(map[string]*Session),
		stopChan:     make(chan struct{}),
	}

	return broker, nil
}

// Start starts the broker services
func (b *Broker) Start(ctx context.Context) error {
	log.Info().Msg("Starting authentication broker services")

	// Start token manager
	if err := b.tokenManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start token manager: %w", err)
	}

	// Start audit logger
	if err := b.auditLogger.Start(ctx); err != nil {
		return fmt.Errorf("failed to start audit logger: %w", err)
	}

	// Start session cleanup goroutine
	b.wg.Add(1)
	go b.sessionCleanup(ctx)

	log.Info().Msg("Authentication broker services started successfully")
	return nil
}

// Stop stops the broker services
func (b *Broker) Stop() error {
	log.Info().Msg("Stopping authentication broker services")

	// Signal stop
	close(b.stopChan)

	// Wait for goroutines to finish
	b.wg.Wait()

	// Stop token manager
	if err := b.tokenManager.Stop(); err != nil {
		log.Error().Err(err).Msg("Error stopping token manager")
	}

	// Stop audit logger
	if err := b.auditLogger.Stop(); err != nil {
		log.Error().Err(err).Msg("Error stopping audit logger")
	}

	log.Info().Msg("Authentication broker services stopped")
	return nil
}

// Authenticate handles authentication requests
func (b *Broker) Authenticate(req *AuthRequest) (*AuthResponse, error) {
	log.Debug().
		Str("user_id", req.UserID).
		Str("source_ip", req.SourceIP).
		Str("target_host", req.TargetHost).
		Str("login_type", req.LoginType).
		Msg("Processing authentication request")

	// Check for existing session
	if session := b.getSession(req.SessionID); session != nil {
		if session.IsActive && session.ExpiresAt.After(time.Now()) {
			return b.createSuccessResponse(session), nil
		}
		// Session expired, clean it up
		b.removeSession(req.SessionID)
	}

	// Apply policy checks
	policyResult, err := b.policyEngine.EvaluateRequest(req)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	if !policyResult.Allowed {
		b.auditLogger.LogAuthEvent(security.AuditEvent{
			EventType:    "authentication_denied",
			UserID:       req.UserID,
			SourceIP:     req.SourceIP,
			TargetHost:   req.TargetHost,
			Success:      false,
			ErrorMessage: policyResult.Reason,
			Timestamp:    time.Now(),
		})

		return &AuthResponse{
			Success:      false,
			ErrorCode:    "POLICY_DENIED",
			ErrorMessage: policyResult.Reason,
		}, nil
	}

	// Select appropriate provider
	provider := b.selectProvider(req, policyResult)
	if provider == nil {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "NO_PROVIDER",
			ErrorMessage: "No suitable authentication provider found",
		}, nil
	}

	// Initiate device flow
	deviceFlow, err := provider.StartDeviceFlow(req)
	if err != nil {
		b.auditLogger.LogAuthEvent(security.AuditEvent{
			EventType:    "device_flow_failed",
			UserID:       req.UserID,
			SourceIP:     req.SourceIP,
			TargetHost:   req.TargetHost,
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
		})

		return &AuthResponse{
			Success:      false,
			ErrorCode:    "DEVICE_FLOW_FAILED",
			ErrorMessage: err.Error(),
		}, nil
	}

	// Generate QR code for device flow
	qrCode, err := GenerateQRCode(deviceFlow.DeviceURL)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate QR code")
		qrCode = "" // Continue without QR code
	}

	// Create pending session
	session := &Session{
		ID:               req.SessionID,
		UserID:           req.UserID,
		Provider:         provider.Name,
		DeviceID:         req.DeviceID,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(b.config.Authentication.TokenLifetime),
		LastAccessed:     time.Now(),
		SourceIP:         req.SourceIP,
		UserAgent:        req.UserAgent,
		TokenFingerprint: deviceFlow.DeviceCode,
		IsActive:         false,
		RiskScore:        policyResult.RiskScore,
		Metadata:         req.Metadata,
	}

	b.setSession(session)

	// Start polling for device authorization in background
	b.wg.Add(1)
	go b.pollDeviceAuthorization(session, provider, deviceFlow)

	return &AuthResponse{
		Success:        true,
		SessionID:      session.ID,
		DeviceCode:     deviceFlow.UserCode,
		DeviceURL:      deviceFlow.DeviceURL,
		QRCode:         qrCode,
		ExpiresAt:      deviceFlow.ExpiresAt,
		RequiresDevice: true,
		RiskScore:      policyResult.RiskScore,
		Metadata:       map[string]interface{}{
			"provider":         provider.Name,
			"polling_interval": deviceFlow.PollingInterval,
		},
	}, nil
}

// CheckSession checks the status of an authentication session
func (b *Broker) CheckSession(sessionID string) (*AuthResponse, error) {
	session := b.getSession(sessionID)
	if session == nil {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "SESSION_NOT_FOUND",
			ErrorMessage: "Session not found",
		}, nil
	}

	if !session.IsActive {
		return &AuthResponse{
			Success:        true,
			SessionID:      sessionID,
			RequiresDevice: true,
			ExpiresAt:      session.ExpiresAt,
			Metadata: map[string]interface{}{
				"status": "pending",
			},
		}, nil
	}

	// Check if session has expired
	if session.ExpiresAt.Before(time.Now()) {
		b.removeSession(sessionID)
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "SESSION_EXPIRED",
			ErrorMessage: "Session has expired",
		}, nil
	}

	return b.createSuccessResponse(session), nil
}

// RefreshSession refreshes an authentication session
func (b *Broker) RefreshSession(sessionID string) (*AuthResponse, error) {
	session := b.getSession(sessionID)
	if session == nil {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "SESSION_NOT_FOUND",
			ErrorMessage: "Session not found",
		}, nil
	}

	// Check if session is close to expiry
	if time.Until(session.ExpiresAt) > b.config.Authentication.RefreshThreshold {
		return b.createSuccessResponse(session), nil
	}

	// Refresh the session
	provider := b.providers[session.Provider]
	if provider == nil {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "PROVIDER_NOT_FOUND",
			ErrorMessage: "Authentication provider not found",
		}, nil
	}

	newToken, err := provider.RefreshToken(session.TokenFingerprint)
	if err != nil {
		b.auditLogger.LogAuthEvent(security.AuditEvent{
			EventType:    "token_refresh_failed",
			UserID:       session.UserID,
			SessionID:    sessionID,
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
		})

		return &AuthResponse{
			Success:      false,
			ErrorCode:    "REFRESH_FAILED",
			ErrorMessage: err.Error(),
		}, nil
	}

	// Update session
	session.TokenFingerprint = newToken.Fingerprint
	session.ExpiresAt = time.Now().Add(b.config.Authentication.TokenLifetime)
	session.LastAccessed = time.Now()

	b.setSession(session)

	return b.createSuccessResponse(session), nil
}

// RevokeSession revokes an authentication session
func (b *Broker) RevokeSession(sessionID string) error {
	session := b.getSession(sessionID)
	if session == nil {
		return fmt.Errorf("session not found")
	}

	// Revoke SSH key if present
	if session.SSHKeyID != "" {
		if err := b.revokeSSHKey(session); err != nil {
			log.Error().
				Err(err).
				Str("session_id", sessionID).
				Str("ssh_key_id", session.SSHKeyID).
				Msg("Failed to revoke SSH key")
		}
	}

	// Remove session
	b.removeSession(sessionID)

	// Audit log
	b.auditLogger.LogAuthEvent(security.AuditEvent{
		EventType: "session_revoked",
		UserID:    session.UserID,
		SessionID: sessionID,
		Success:   true,
		Timestamp: time.Now(),
	})

	return nil
}

// Helper methods

func (b *Broker) getSession(sessionID string) *Session {
	b.sessionMutex.RLock()
	defer b.sessionMutex.RUnlock()
	return b.sessions[sessionID]
}

func (b *Broker) setSession(session *Session) {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()
	b.sessions[session.ID] = session
}

func (b *Broker) removeSession(sessionID string) {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()
	delete(b.sessions, sessionID)
}

func (b *Broker) createSuccessResponse(session *Session) *AuthResponse {
	return &AuthResponse{
		Success:      true,
		UserID:       session.UserID,
		Email:        session.Email,
		Groups:       session.Groups,
		SessionID:    session.ID,
		ExpiresAt:    session.ExpiresAt,
		SSHPublicKey: session.SSHKeyID, // This would be the actual public key
		RiskScore:    session.RiskScore,
		Metadata: map[string]interface{}{
			"provider":       session.Provider,
			"device_trusted": session.DeviceTrusted,
			"last_accessed":  session.LastAccessed,
		},
	}
}

func (b *Broker) selectProvider(req *AuthRequest, policyResult *PolicyResult) *OIDCProvider {
	// For now, select the first available provider
	// In a full implementation, this would consider provider priority,
	// user preferences, policy requirements, etc.
	for _, provider := range b.providers {
		if provider.Config.EnabledForLogin {
			return provider
		}
	}
	return nil
}

func (b *Broker) pollDeviceAuthorization(session *Session, provider *OIDCProvider, deviceFlow *DeviceFlow) {
	defer b.wg.Done()

	ticker := time.NewTicker(time.Duration(deviceFlow.PollingInterval) * time.Second)
	defer ticker.Stop()

	timeout := time.NewTimer(time.Until(deviceFlow.ExpiresAt))
	defer timeout.Stop()

	for {
		select {
		case <-b.stopChan:
			return
		case <-timeout.C:
			// Device flow expired
			b.removeSession(session.ID)
			return
		case <-ticker.C:
			// Poll for authorization
			token, err := provider.PollDeviceAuthorization(deviceFlow.DeviceCode)
			if err != nil {
				// Handle specific error types
				if err.Error() == "authorization_pending" {
					continue // Keep polling
				}
				// Other errors mean failure
				b.auditLogger.LogAuthEvent(security.AuditEvent{
					EventType:    "device_authorization_failed",
					UserID:       session.UserID,
					SessionID:    session.ID,
					Success:      false,
					ErrorMessage: err.Error(),
					Timestamp:    time.Now(),
				})
				b.removeSession(session.ID)
				return
			}

			// Authorization successful
			userInfo, err := provider.GetUserInfo(token)
			if err != nil {
				log.Error().
					Err(err).
					Str("session_id", session.ID).
					Msg("Failed to get user info")
				b.removeSession(session.ID)
				return
			}

			// Update session with user info
			session.Email = userInfo.Email
			session.Groups = userInfo.Groups
			session.TokenFingerprint = token.Fingerprint
			session.IsActive = true
			session.DeviceTrusted = userInfo.DeviceTrusted

			// Generate SSH key if needed
			if session.SSHKeyID == "" {
				sshKey, err := b.generateSSHKey(session)
				if err != nil {
					log.Error().
						Err(err).
						Str("session_id", session.ID).
						Msg("Failed to generate SSH key")
				} else {
					session.SSHKeyID = sshKey.ID
				}
			}

			b.setSession(session)

			// Audit log
			b.auditLogger.LogAuthEvent(security.AuditEvent{
				EventType: "authentication_successful",
				UserID:    session.UserID,
				Email:     session.Email,
				Groups:    session.Groups,
				SessionID: session.ID,
				Provider:  provider.Name,
				Success:   true,
				Timestamp: time.Now(),
			})

			return
		}
	}
}

func (b *Broker) sessionCleanup(ctx context.Context) {
	defer b.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			var expiredSessions []string

			b.sessionMutex.RLock()
			for id, session := range b.sessions {
				if session.ExpiresAt.Before(now) {
					expiredSessions = append(expiredSessions, id)
				}
			}
			b.sessionMutex.RUnlock()

			// Clean up expired sessions
			for _, sessionID := range expiredSessions {
				if err := b.RevokeSession(sessionID); err != nil {
					log.Error().
						Err(err).
						Str("session_id", sessionID).
						Msg("Failed to revoke expired session")
				}
			}

			if len(expiredSessions) > 0 {
				log.Info().
					Int("count", len(expiredSessions)).
					Msg("Cleaned up expired sessions")
			}
		}
	}
}

func (b *Broker) generateSSHKey(session *Session) (*SSHKey, error) {
	// This would generate an SSH key pair and return the key info
	// For now, return a placeholder
	return &SSHKey{
		ID:        fmt.Sprintf("ssh-key-%s", session.ID),
		PublicKey: "ssh-rsa AAAAB3NzaC1yc2E...",
		ExpiresAt: session.ExpiresAt,
	}, nil
}

func (b *Broker) revokeSSHKey(session *Session) error {
	// This would revoke the SSH key
	// For now, just log
	log.Info().
		Str("session_id", session.ID).
		Str("ssh_key_id", session.SSHKeyID).
		Msg("Revoking SSH key")
	return nil
}

// SSHKey represents an SSH key
type SSHKey struct {
	ID        string
	PublicKey string
	ExpiresAt time.Time
}