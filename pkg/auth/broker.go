package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	oidcmetrics "github.com/scttfrdmn/oidc-pam/pkg/metrics"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
	sshpkg "github.com/scttfrdmn/oidc-pam/pkg/ssh"
)

// Broker manages authentication requests and OIDC provider interactions
type Broker struct {
	config                *config.Config
	providers             map[string]*OIDCProvider
	tokenManager          *TokenManager
	policyEngine          *PolicyEngine
	auditLogger           *security.AuditLogger
	sessions              map[string]*Session
	sessionMutex          sync.RWMutex
	keyManager            *sshpkg.KeyManager
	authorizedKeysManager *sshpkg.AuthorizedKeysManager
	stopChan              chan struct{}
	wg                    sync.WaitGroup
	metrics               *oidcmetrics.Metrics // nil when metrics are disabled
	pendingFlows          int64                // atomic counter of in-progress device authorization goroutines
	version               string               // build version, set via SetVersion; reported by Status
	startedAt             time.Time            // when Start ran; zero until then. Reported by Status
}

// SetMetrics attaches a Metrics instance to the broker and its policy engine.
// Call this after NewBroker and before Start.
func (b *Broker) SetMetrics(m *oidcmetrics.Metrics) {
	b.metrics = m
	b.policyEngine.SetMetrics(m)
}

// Session represents an active authentication session
type Session struct {
	ID       string
	UserID   string
	Email    string
	Groups   []string
	Provider string
	// LoginType is the kind of login this session was opened for ("ssh",
	// "console", "gui"), as classified by the PAM client. The broker applies
	// per-login-type policy on it, and `oidc-admin sessions` reports it.
	LoginType        string
	DeviceID         string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	LastAccessed     time.Time
	SourceIP         string
	UserAgent        string
	TokenFingerprint string
	// TokenID identifies this session's entry in the TokenManager, which holds
	// the access/refresh/ID tokens encrypted with AES-256-GCM. The tokens
	// themselves are deliberately NOT fields on Session: Session is passed
	// around, logged and copied, and a refresh token in it is a long-lived
	// credential sitting in plaintext in the broker's heap.
	TokenID       string
	SSHKeyID      string
	SSHPublicKey  string
	IsActive      bool
	RiskScore     int
	DeviceTrusted bool
	Metadata      map[string]interface{}
}

// AuthRequest represents an authentication request
type AuthRequest struct {
	UserID     string
	SourceIP   string
	UserAgent  string
	TargetHost string
	LoginType  string // "ssh", "console", "gui"
	DeviceID   string
	SessionID  string
	Timestamp  time.Time
	Metadata   map[string]interface{}
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

	// Validate security configuration. The key must be a base64-encoded 32-byte
	// value (as produced by GenerateKey); it is used directly as the AES-256 key
	// with no passphrase stretching.
	if cfg.Security.TokenEncryptionKey == "" {
		return nil, fmt.Errorf("token encryption key is required for security")
	}
	if err := security.ValidateKeyString(cfg.Security.TokenEncryptionKey); err != nil {
		return nil, fmt.Errorf("invalid token_encryption_key: %w", err)
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
		provider, err := NewOIDCProvider(providerConfig, cfg.Security)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider '%s': %w", providerConfig.Name, err)
		}
		providers[providerConfig.Name] = provider
	}

	broker := &Broker{
		config:                cfg,
		providers:             providers,
		tokenManager:          tokenManager,
		policyEngine:          policyEngine,
		auditLogger:           auditLogger,
		sessions:              make(map[string]*Session),
		keyManager:            sshpkg.NewKeyManager("/var/lib/oidc-pam/ssh-keys"),
		authorizedKeysManager: sshpkg.NewAuthorizedKeysManager("/home"),
		stopChan:              make(chan struct{}),
	}

	return broker, nil
}

// Start starts the broker services
func (b *Broker) Start(ctx context.Context) error {
	log.Info().Msg("Starting authentication broker services")

	b.startedAt = time.Now()

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

// DroppedAuditEvents returns the cumulative count of audit events dropped by
// the audit logger.  Used to back the oidc_audit_events_dropped_total metric.
func (b *Broker) DroppedAuditEvents() int64 {
	return b.auditLogger.DroppedEvents()
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
	// Validate field lengths to prevent log flooding and memory exhaustion.
	if len(req.UserID) > 256 || len(req.SourceIP) > 45 ||
		len(req.TargetHost) > 253 || len(req.LoginType) > 16 {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "INVALID_REQUEST",
			ErrorMessage: "request field exceeds maximum length",
		}, nil
	}

	log.Debug().
		Str("user_id", req.UserID).
		Str("source_ip", req.SourceIP).
		Str("target_host", req.TargetHost).
		Str("login_type", req.LoginType).
		Msg("Processing authentication request")

	// Check for existing session — atomically return valid sessions or remove expired ones.
	// Pass req.UserID so the helper rejects sessions belonging to other users (prevents hijacking).
	if session, valid := b.getAndRemoveIfExpiredSession(req.SessionID, req.UserID); valid {
		return b.createSuccessResponse(session), nil
	}

	// Check per-user session limit
	maxSessions := b.config.Authentication.MaxConcurrentSessions
	if maxSessions > 0 && b.countUserSessions(req.UserID) >= maxSessions {
		log.Warn().
			Str("user_id", req.UserID).
			Int("max_sessions", maxSessions).
			Msg("Maximum concurrent sessions reached for user")
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "TOO_MANY_SESSIONS",
			ErrorMessage: "Maximum concurrent sessions reached",
		}, nil
	}

	// Apply policy checks
	policyResult, err := b.policyEngine.EvaluateRequest(req)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	if !policyResult.Allowed {
		if b.metrics != nil {
			b.metrics.RecordAuth("", "policy_denied", "POLICY_DENIED")
		}
		b.auditLogger.LogAuthEvent(security.AuditEvent{
			EventType:    "authentication_denied",
			UserID:       req.UserID,
			SourceIP:     req.SourceIP,
			TargetHost:   req.TargetHost,
			Success:      false,
			ErrorMessage: policyResult.Reason,
			Timestamp:    time.Now(),
		})

		log.Warn().
			Str("user_id", req.UserID).
			Str("reason", policyResult.Reason).
			Msg("Authentication denied by policy")

		return &AuthResponse{
			Success:      false,
			ErrorCode:    "POLICY_DENIED",
			ErrorMessage: "Access denied by policy",
		}, nil
	}

	// Select appropriate provider
	provider := b.selectProvider()
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
			ErrorMessage: sanitizeErrorForClient(err),
		}, nil
	}

	// Generate QR code for device flow
	qrCode, err := GenerateQRCode(deviceFlow.DeviceURL)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate QR code")
		qrCode = "" // Continue without QR code
	}

	// Create pending session — always generate the session ID server-side;
	// never trust the client-supplied value to prevent session fixation/hijacking.
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	session := &Session{
		ID:               sessionID,
		UserID:           req.UserID,
		Provider:         provider.Name,
		LoginType:        req.LoginType,
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

	// Enforce a cap on concurrent device-flow goroutines to prevent goroutine exhaustion DoS.
	const maxPendingFlows = 100
	if atomic.AddInt64(&b.pendingFlows, 1) > maxPendingFlows {
		atomic.AddInt64(&b.pendingFlows, -1)
		b.removeSession(session.ID)
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "RATE_LIMITED",
			ErrorMessage: "too many pending device authorization flows; try again later",
		}, nil
	}

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
		Metadata: map[string]interface{}{
			"provider":         provider.Name,
			"polling_interval": deviceFlow.PollingInterval,
		},
	}, nil
}

// CheckSession checks the status of an authentication session.
// userID must match the session owner — cross-user session access is rejected.
func (b *Broker) CheckSession(sessionID, userID string) (*AuthResponse, error) {
	session := b.getSession(sessionID)
	if session == nil {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "SESSION_NOT_FOUND",
			ErrorMessage: "Session not found",
		}, nil
	}

	if session.UserID != userID {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "FORBIDDEN",
			ErrorMessage: "session does not belong to requesting user",
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

	// Clone before mutation to avoid a data race: getSession returns the raw
	// pointer stored in the map, so writing to it without a lock races with
	// any concurrent reader that also holds that pointer.
	updated := *session
	updated.LastAccessed = time.Now()
	b.setSession(&updated)

	return b.createSuccessResponse(session), nil
}

// RefreshSession refreshes an authentication session.
// userID must match the session owner — cross-user session refreshes are rejected.
func (b *Broker) RefreshSession(sessionID, userID string) (*AuthResponse, error) {
	session := b.getSession(sessionID)
	if session == nil {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "SESSION_NOT_FOUND",
			ErrorMessage: "Session not found",
		}, nil
	}

	if session.UserID != userID {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "FORBIDDEN",
			ErrorMessage: "session does not belong to requesting user",
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

	if session.TokenID == "" {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "NO_REFRESH_TOKEN",
			ErrorMessage: "No refresh token available for this session",
		}, nil
	}

	// The refresh token lives encrypted in the token store; decrypt it only for
	// the duration of this call rather than keeping a copy on the session.
	storedToken, err := b.tokenManager.GetToken(session.TokenID)
	if err != nil {
		log.Warn().
			Err(err).
			Str("session_id", sessionID).
			Msg("Session has no usable stored token; cannot refresh")
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "NO_REFRESH_TOKEN",
			ErrorMessage: "No refresh token available for this session",
		}, nil
	}
	if storedToken.RefreshToken == "" {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "NO_REFRESH_TOKEN",
			ErrorMessage: "No refresh token available for this session",
		}, nil
	}

	refreshCtx, refreshCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer refreshCancel()

	newToken, err := provider.RefreshToken(refreshCtx, storedToken.RefreshToken)
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
			ErrorMessage: sanitizeErrorForClient(err),
		}, nil
	}

	// Store the refreshed token and point the session at it. The previous entry
	// is revoked afterwards: a rotated refresh token is no longer usable, and
	// leaving it in the store would keep dead credential material in memory.
	newTokenID, err := b.tokenManager.StoreToken(newToken, session.UserID, sessionID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", sessionID).
			Msg("Failed to store refreshed token")
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "REFRESH_FAILED",
			ErrorMessage: "Failed to store refreshed token",
		}, nil
	}

	previousTokenID := session.TokenID

	// Update session with new token data
	session.TokenFingerprint = newToken.Fingerprint
	session.TokenID = newTokenID
	session.ExpiresAt = time.Now().Add(b.config.Authentication.TokenLifetime)
	session.LastAccessed = time.Now()

	b.setSession(session)

	if previousTokenID != "" && previousTokenID != newTokenID {
		if err := b.tokenManager.RevokeToken(previousTokenID); err != nil {
			log.Debug().
				Err(err).
				Str("session_id", sessionID).
				Msg("Could not revoke the pre-refresh token")
		}
	}

	b.auditLogger.LogAuthEvent(security.AuditEvent{
		EventType: "token_refreshed",
		UserID:    session.UserID,
		SessionID: sessionID,
		Success:   true,
		Timestamp: time.Now(),
	})

	return b.createSuccessResponse(session), nil
}

// RevokeSession revokes an authentication session.
// userID must match the session owner — cross-user revocation is rejected.
func (b *Broker) RevokeSession(sessionID, userID string) error {
	session := b.getSession(sessionID)
	if session == nil {
		return fmt.Errorf("session not found")
	}

	if session.UserID != userID {
		return fmt.Errorf("session does not belong to requesting user")
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

	// Destroy the session's stored tokens. Dropping the session alone would leave
	// its access and refresh tokens in the store until the 5-minute sweep, and a
	// refresh token outlives the session it was issued for.
	if err := b.tokenManager.RevokeSessionTokens(sessionID); err != nil {
		log.Error().
			Err(err).
			Str("session_id", sessionID).
			Msg("Failed to revoke stored tokens for session")
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

// getAndRemoveIfExpiredSession atomically checks a session and removes it if it
// is expired or inactive. Returns (session, true) only if the session is valid,
// active, and owned by userID. Returns (nil, false) if the session doesn't
// exist, belongs to a different user, or was expired/inactive (and is removed).
func (b *Broker) getAndRemoveIfExpiredSession(sessionID, userID string) (*Session, bool) {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()
	session, ok := b.sessions[sessionID]
	if !ok {
		return nil, false
	}
	// Reject sessions belonging to a different user (prevents cross-user session hijacking).
	if session.UserID != userID {
		return nil, false
	}
	if session.IsActive && session.ExpiresAt.After(time.Now()) {
		return session, true // valid — do not remove
	}
	delete(b.sessions, sessionID) // expired/inactive — remove atomically
	return nil, false
}

func (b *Broker) setSession(session *Session) {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()
	b.sessions[session.ID] = session
}

func (b *Broker) removeSession(sessionID string) {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()
	if s, ok := b.sessions[sessionID]; ok && s.IsActive {
		if b.metrics != nil {
			b.metrics.ActiveSessions.Dec()
		}
	}
	delete(b.sessions, sessionID)
}

// countUserSessions returns the number of active sessions for the given user.
func (b *Broker) countUserSessions(userID string) int {
	b.sessionMutex.RLock()
	defer b.sessionMutex.RUnlock()

	count := 0
	for _, session := range b.sessions {
		if session.UserID == userID {
			count++
		}
	}
	return count
}

func (b *Broker) createSuccessResponse(session *Session) *AuthResponse {
	return &AuthResponse{
		Success:      true,
		UserID:       session.UserID,
		Email:        session.Email,
		Groups:       session.Groups,
		SessionID:    session.ID,
		ExpiresAt:    session.ExpiresAt,
		SSHPublicKey: session.SSHPublicKey,
		RiskScore:    session.RiskScore,
		Metadata: map[string]interface{}{
			"provider":       session.Provider,
			"device_trusted": session.DeviceTrusted,
			"last_accessed":  session.LastAccessed,
		},
	}
}

// selectProvider returns the provider a new login should be sent to, or nil if
// the configuration has none that can serve one.
//
// It takes no request or policy argument on purpose: nothing about the request
// influences the choice today. The previous signature accepted both and read
// neither, which is how it went unnoticed that the body ranged over a map — so
// with more than one login-enabled provider, consecutive logins on the same host
// could be sent to different identity providers at random, and `priority` was
// parsed from the config and never read. Reinstate the parameters along with the
// logic that actually needs them.
func (b *Broker) selectProvider() *OIDCProvider {
	candidates := b.loginProviders()
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0]
}

// loginProviders returns every provider eligible to serve a login, in
// precedence order: by `priority` ascending, then by name.
//
// Priority 1 is the most preferred, matching the shipped configurations, where
// the primary provider is `priority: 1` and the failover provider is
// `priority: 2`. A provider that does not set `priority` at all sorts *after*
// every provider that does, so omitting the field cannot outrank an explicit
// declaration.
func (b *Broker) loginProviders() []*OIDCProvider {
	candidates := make([]*OIDCProvider, 0, len(b.providers))
	for _, provider := range b.providers {
		// verification_only means the provider may confirm an identity but must
		// not be the one a login is issued against, so it is not a candidate
		// even if enabled_for_login is also set. The two together are
		// contradictory config; this resolves it the safe way.
		if provider.Config.EnabledForLogin && !provider.Config.VerificationOnly {
			candidates = append(candidates, provider)
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		left, right := providerPriority(candidates[i]), providerPriority(candidates[j])
		if left != right {
			return left < right
		}
		// Ties broken by name so that the order is stable across restarts and
		// independent of Go's map iteration order.
		return candidates[i].Name < candidates[j].Name
	})

	return candidates
}

// providerPriority maps a provider's configured priority onto its sort key,
// translating "unset" (0, and any nonsensical negative value) to "last".
func providerPriority(provider *OIDCProvider) int {
	if provider.Config.Priority <= 0 {
		return math.MaxInt
	}
	return provider.Config.Priority
}

func (b *Broker) pollDeviceAuthorization(session *Session, provider *OIDCProvider, deviceFlow *DeviceFlow) {
	defer b.wg.Done()
	defer atomic.AddInt64(&b.pendingFlows, -1)

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
			// Poll for authorization using a per-attempt context with timeout.
			pollCtx, pollCancel := context.WithTimeout(context.Background(), 30*time.Second)
			token, err := provider.PollDeviceAuthorization(pollCtx, deviceFlow.DeviceCode, deviceFlow.Nonce)
			pollCancel()
			if err != nil {
				// Handle specific error types
				if err.Error() == "authorization_pending" {
					continue // Keep polling
				}
				// Other errors mean failure. Use a bounded error-code enum for the
				// metric label (never the raw error string) to avoid Prometheus
				// cardinality explosion and leaking transient infra detail.
				if b.metrics != nil {
					b.metrics.RecordAuth(provider.Name, "failure", classifyPollError(err))
				}
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
				if b.metrics != nil {
					b.metrics.RecordAuth(provider.Name, "failure", "USER_INFO_FAILED")
				}
				b.removeSession(session.ID)
				return
			}

			// SECURITY (C-1): bind the authenticated OIDC identity to the local
			// username this login was requested for. Without this, any IdP user
			// could authenticate as any local account (including root). Fail
			// closed on any mismatch or misconfiguration.
			if err := b.verifyIdentityBinding(provider, userInfo, session.UserID); err != nil {
				log.Warn().
					Err(err).
					Str("session_id", session.ID).
					Str("requested_user", session.UserID).
					Str("oidc_subject", userInfo.Subject).
					Msg("Rejected authentication: OIDC identity does not match requested local user")
				if b.metrics != nil {
					b.metrics.RecordAuth(provider.Name, "failure", "IDENTITY_MISMATCH")
				}
				b.auditLogger.LogAuthEvent(security.AuditEvent{
					EventType:    "authentication_denied",
					UserID:       session.UserID,
					Email:        userInfo.Email,
					SessionID:    session.ID,
					Success:      false,
					ErrorCode:    "IDENTITY_MISMATCH",
					ErrorMessage: err.Error(),
					Timestamp:    time.Now(),
				})
				b.removeSession(session.ID)
				return
			}

			// SECURITY (H-1): enforce required group membership. RequiredGroups
			// was previously collected by the policy engine but never checked.
			if err := b.verifyRequiredGroups(userInfo.Groups); err != nil {
				log.Warn().
					Err(err).
					Str("session_id", session.ID).
					Str("requested_user", session.UserID).
					Msg("Rejected authentication: required group membership not satisfied")
				if b.metrics != nil {
					b.metrics.RecordAuth(provider.Name, "failure", "GROUP_DENIED")
				}
				b.auditLogger.LogAuthEvent(security.AuditEvent{
					EventType:    "authentication_denied",
					UserID:       session.UserID,
					Email:        userInfo.Email,
					Groups:       userInfo.Groups,
					SessionID:    session.ID,
					Success:      false,
					ErrorCode:    "GROUP_DENIED",
					ErrorMessage: err.Error(),
					Timestamp:    time.Now(),
				})
				b.removeSession(session.ID)
				return
			}

			// Hand the tokens to the token manager, which encrypts them with
			// AES-256-GCM, and keep only its ID on the session. The session must
			// never carry the refresh token itself: it is a long-lived credential,
			// and Session is copied, passed around and reachable from a heap dump.
			tokenID, err := b.tokenManager.StoreToken(token, session.UserID, session.ID)
			if err != nil {
				log.Error().
					Err(err).
					Str("session_id", session.ID).
					Msg("Rejected authentication: could not store tokens securely")
				if b.metrics != nil {
					b.metrics.RecordAuth(provider.Name, "failure", "TOKEN_STORE_FAILED")
				}
				b.auditLogger.LogAuthEvent(security.AuditEvent{
					EventType:    "authentication_denied",
					UserID:       session.UserID,
					Email:        userInfo.Email,
					SessionID:    session.ID,
					Success:      false,
					ErrorCode:    "TOKEN_STORE_FAILED",
					ErrorMessage: err.Error(),
					Timestamp:    time.Now(),
				})
				b.removeSession(session.ID)
				return
			}

			// Clone before mutation: getSession returns the raw pointer stored in
			// the map; writing to it without a lock races with concurrent readers.
			updated := *session
			updated.Email = userInfo.Email
			updated.Groups = userInfo.Groups
			updated.TokenFingerprint = token.Fingerprint
			updated.TokenID = tokenID
			updated.IsActive = true
			updated.DeviceTrusted = userInfo.DeviceTrusted

			// Generate SSH key if needed
			if updated.SSHKeyID == "" {
				sshKey, err := b.generateSSHKey(&updated)
				if err != nil {
					log.Error().
						Err(err).
						Str("session_id", updated.ID).
						Msg("Failed to generate SSH key")
				} else {
					updated.SSHKeyID = sshKey.ID
					updated.SSHPublicKey = sshKey.PublicKey
				}
			}

			b.setSession(&updated)

			if b.metrics != nil {
				b.metrics.RecordAuth(provider.Name, "success", "")
				b.metrics.ActiveSessions.Inc()
			}

			// Record the login location so future logins from the same
			// /24 subnet or country are not flagged as unusual.
			b.policyEngine.RecordLocation(session.UserID, session.SourceIP)

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
			b.expireSessions(time.Now())
		}
	}
}

// expireSessions removes every session that has passed its expiry or idle
// timeout as of now, and tears down what each one owned. Separate from the
// ticker loop so it can be tested directly.
func (b *Broker) expireSessions(now time.Time) {
	// Atomically collect and remove expired sessions under a single write lock
	// to avoid TOCTOU race between identifying and removing sessions.
	var expiredSessions []*Session
	idleTimeout := b.config.Authentication.IdleTimeout
	b.sessionMutex.Lock()
	for id, session := range b.sessions {
		idleExpired := idleTimeout > 0 && now.Sub(session.LastAccessed) > idleTimeout
		if session.ExpiresAt.Before(now) || idleExpired {
			expiredSessions = append(expiredSessions, session)
			delete(b.sessions, id)
		}
	}
	b.sessionMutex.Unlock()

	if b.metrics != nil {
		for _, session := range expiredSessions {
			if session.IsActive {
				b.metrics.ActiveSessions.Dec()
			}
		}
	}

	// Perform SSH key revocation and audit logging outside the lock.
	// Sessions are already removed from the map, so no TOCTOU risk.
	for _, session := range expiredSessions {
		if session.SSHKeyID != "" {
			if err := b.revokeSSHKey(session); err != nil {
				log.Error().
					Err(err).
					Str("session_id", session.ID).
					Str("ssh_key_id", session.SSHKeyID).
					Msg("Failed to revoke SSH key for expired session")
			}
		}

		// An expired session's tokens are dead credential material; the token
		// store's own sweep would only catch them once the tokens themselves
		// expire, which can be later than the session.
		if b.tokenManager != nil {
			if err := b.tokenManager.RevokeSessionTokens(session.ID); err != nil {
				log.Error().
					Err(err).
					Str("session_id", session.ID).
					Msg("Failed to revoke stored tokens for expired session")
			}
		}

		if b.auditLogger != nil {
			b.auditLogger.LogAuthEvent(security.AuditEvent{
				EventType: "session_expired",
				UserID:    session.UserID,
				SessionID: session.ID,
				Success:   true,
				Timestamp: now,
			})
		}
	}

	if len(expiredSessions) > 0 {
		log.Info().
			Int("count", len(expiredSessions)).
			Msg("Cleaned up expired sessions")
	}
}

func (b *Broker) generateSSHKey(session *Session) (*SSHKey, error) {
	if b.keyManager == nil || b.authorizedKeysManager == nil {
		return nil, fmt.Errorf("SSH key manager not initialized")
	}

	// Generate an RSA key pair with the username as the comment prefix
	sshKey, err := b.keyManager.GenerateKey(session.UserID)
	if err != nil {
		if b.metrics != nil {
			b.metrics.RecordSSHKeyOp("generate", "failure")
		}
		return nil, fmt.Errorf("failed to generate SSH key pair: %w", err)
	}

	// Persist the key pair on disk, keyed by session ID so multiple
	// concurrent sessions for the same user don't overwrite each other.
	if err := b.keyManager.SaveKey(session.ID, sshKey); err != nil {
		if b.metrics != nil {
			b.metrics.RecordSSHKeyOp("generate", "failure")
		}
		return nil, fmt.Errorf("failed to save SSH key: %w", err)
	}

	// Append the public key to the user's authorized_keys file
	if err := b.authorizedKeysManager.AddPublicKey(session.UserID, sshKey.PublicKey); err != nil {
		// Best-effort cleanup: remove the stored key if we couldn't authorize it
		_ = b.keyManager.DeleteKey(session.ID)
		if b.metrics != nil {
			b.metrics.RecordSSHKeyOp("generate", "failure")
		}
		return nil, fmt.Errorf("failed to add public key to authorized_keys: %w", err)
	}

	log.Info().
		Str("session_id", session.ID).
		Str("user_id", session.UserID).
		Time("expires_at", sshKey.ExpiresAt).
		Msg("SSH key generated and authorized")

	if b.metrics != nil {
		b.metrics.RecordSSHKeyOp("generate", "success")
	}

	return &SSHKey{
		ID:        session.ID,
		PublicKey: string(sshKey.PublicKey),
		ExpiresAt: sshKey.ExpiresAt,
	}, nil
}

func (b *Broker) revokeSSHKey(session *Session) error {
	if b.keyManager == nil || b.authorizedKeysManager == nil {
		return nil
	}

	// Load the stored key to obtain the public key bytes needed for removal
	sshKey, err := b.keyManager.LoadKey(session.SSHKeyID)
	if err != nil {
		// Key may have already been deleted; treat as success
		log.Debug().
			Err(err).
			Str("session_id", session.ID).
			Str("ssh_key_id", session.SSHKeyID).
			Msg("SSH key not found during revocation (may already be deleted)")
		return nil
	}

	// Remove from authorized_keys (best effort — do not abort on failure)
	if err := b.authorizedKeysManager.RemovePublicKey(session.UserID, sshKey.PublicKey); err != nil {
		log.Warn().
			Err(err).
			Str("session_id", session.ID).
			Str("user_id", session.UserID).
			Msg("Failed to remove public key from authorized_keys during revocation")
	}

	// Delete the key files from disk
	if err := b.keyManager.DeleteKey(session.SSHKeyID); err != nil {
		if b.metrics != nil {
			b.metrics.RecordSSHKeyOp("revoke", "failure")
		}
		return fmt.Errorf("failed to delete SSH key files: %w", err)
	}

	log.Info().
		Str("session_id", session.ID).
		Str("ssh_key_id", session.SSHKeyID).
		Msg("SSH key revoked")

	if b.metrics != nil {
		b.metrics.RecordSSHKeyOp("revoke", "success")
	}

	return nil
}

// generateSessionID returns a cryptographically random 64-character hex session ID.
// It returns an error rather than degrading to a predictable fallback — a crypto/rand
// failure indicates a serious system problem that must not be silently ignored.
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// sanitizeErrorForClient logs the full internal error and returns a generic
// message safe to surface to PAM / end users (avoids leaking OIDC internals).
func sanitizeErrorForClient(err error) string {
	log.Debug().Err(err).Msg("internal auth error")
	msg := err.Error()
	switch {
	case strings.Contains(msg, "authorization_pending"):
		return "authorization pending"
	case strings.Contains(msg, "slow_down"):
		return "authorization pending"
	case strings.Contains(msg, "access_denied"):
		return "access denied by identity provider"
	case strings.Contains(msg, "expired_token"):
		return "device code expired"
	default:
		return "authentication failed"
	}
}

// verifyIdentityBinding ensures the authenticated OIDC identity actually maps
// to the local username the login was requested for (requestedUser). This is
// the authn->authz boundary: it prevents an IdP user from logging in as an
// arbitrary local account. It fails closed — any misconfiguration or mismatch
// returns an error rather than allowing the login.
//
// The expected local username is resolved from the configured username_claim
// (falling back to the standard "preferred_username" claim). Comparison is
// case-insensitive on the local-part, matching typical POSIX/login behavior.
func (b *Broker) verifyIdentityBinding(provider *OIDCProvider, userInfo *UserInfo, requestedUser string) error {
	if userInfo == nil {
		return fmt.Errorf("no user info available")
	}
	requested := strings.TrimSpace(strings.ToLower(requestedUser))
	if requested == "" {
		return fmt.Errorf("requested username is empty")
	}

	claimName := strings.TrimSpace(provider.Config.UserMapping.UsernameClaim)
	if claimName == "" {
		// Fail closed: without an explicit mapping we will not guess which
		// claim authorizes a local login.
		return fmt.Errorf("username_claim is not configured for provider %q; refusing to bind identity", provider.Config.Name)
	}

	mapped, err := claimToUsername(userInfo, claimName)
	if err != nil {
		return err
	}
	mapped = strings.TrimSpace(strings.ToLower(mapped))
	if mapped == "" {
		return fmt.Errorf("username_claim %q produced an empty username", claimName)
	}

	// If the claim is an email (e.g. preferred_username/email), allow matching
	// either the full value or its local-part against the requested user.
	if mapped == requested {
		return nil
	}
	if local, _, found := strings.Cut(mapped, "@"); found && local == requested {
		return nil
	}
	return fmt.Errorf("authenticated identity %q (claim %q) does not match requested local user %q", mapped, claimName, requested)
}

// claimToUsername extracts a string username from the resolved claims using the
// configured claim name, with sensible fallbacks to well-known UserInfo fields.
func claimToUsername(userInfo *UserInfo, claimName string) (string, error) {
	if userInfo.Claims != nil {
		if v, ok := userInfo.Claims[claimName]; ok {
			if s, ok := v.(string); ok {
				return s, nil
			}
			return "", fmt.Errorf("username_claim %q is not a string", claimName)
		}
	}
	// Fallbacks for the common standard claims even if not present in the raw map.
	switch claimName {
	case "preferred_username", "sub":
		if userInfo.Subject != "" {
			return userInfo.Subject, nil
		}
	case "email":
		if userInfo.Email != "" {
			return userInfo.Email, nil
		}
	}
	return "", fmt.Errorf("username_claim %q not present in token claims", claimName)
}

// classifyPollError maps a device-authorization polling error to a small, fixed
// set of metric label values. Raw error strings must never be used as metric
// labels (unbounded cardinality + info leak).
func classifyPollError(err error) string {
	if err == nil {
		return "OK"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "nonce"):
		return "NONCE_INVALID"
	case strings.Contains(msg, "verify id token"), strings.Contains(msg, "claim validation"):
		return "ID_TOKEN_INVALID"
	case strings.Contains(msg, "token error"):
		return "TOKEN_ERROR"
	case strings.Contains(msg, "access_denied"):
		return "ACCESS_DENIED"
	case strings.Contains(msg, "expired"):
		return "EXPIRED"
	case strings.Contains(msg, "decode"):
		return "DECODE_ERROR"
	case strings.Contains(msg, "failed to poll"), strings.Contains(msg, "connection"), strings.Contains(msg, "timeout"):
		return "NETWORK_ERROR"
	default:
		return "POLL_FAILED"
	}
}

// verifyRequiredGroups enforces that the authenticated user is a member of all
// globally required groups (Authentication.RequireGroups). Returns nil when no
// groups are required. Comparison is exact and case-sensitive (group names are
// provider-defined identifiers).
func (b *Broker) verifyRequiredGroups(userGroups []string) error {
	required := b.config.Authentication.RequireGroups
	if len(required) == 0 {
		return nil
	}
	have := make(map[string]struct{}, len(userGroups))
	for _, g := range userGroups {
		have[g] = struct{}{}
	}
	var missing []string
	for _, r := range required {
		if _, ok := have[r]; !ok {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("user is not a member of required group(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

// SSHKey represents an SSH key
type SSHKey struct {
	ID        string
	PublicKey string
	ExpiresAt time.Time
}
