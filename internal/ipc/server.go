package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/auth"
)

// Server handles IPC communication with PAM modules
type Server struct {
	socketPath string
	broker     *auth.Broker
	listener   net.Listener
	stopChan   chan struct{}
	wg         sync.WaitGroup
	stopOnce   sync.Once
}

// Request represents a request from PAM module
type Request struct {
	Type      string                 `json:"type"`
	UserID    string                 `json:"user_id"`
	SourceIP  string                 `json:"source_ip"`
	UserAgent string                 `json:"user_agent"`
	TargetHost string                `json:"target_host"`
	LoginType string                 `json:"login_type"`
	DeviceID  string                 `json:"device_id"`
	SessionID string                 `json:"session_id"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// Response represents a response to PAM module
type Response struct {
	Success          bool                   `json:"success"`
	UserID           string                 `json:"user_id"`
	Email            string                 `json:"email"`
	Groups           []string               `json:"groups"`
	SessionID        string                 `json:"session_id"`
	DeviceCode       string                 `json:"device_code"`
	DeviceURL        string                 `json:"device_url"`
	QRCode           string                 `json:"qr_code"`
	ExpiresAt        time.Time              `json:"expires_at"`
	SSHPublicKey     string                 `json:"ssh_public_key"`
	RequiresDevice   bool                   `json:"requires_device"`
	RequiresApproval bool                   `json:"requires_approval"`
	ErrorCode        string                 `json:"error_code"`
	ErrorMessage     string                 `json:"error_message"`
	Instructions     string                 `json:"instructions"`
	RiskScore        int                    `json:"risk_score"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// NewServer creates a new IPC server
func NewServer(socketPath string, broker *auth.Broker) (*Server, error) {
	return &Server{
		socketPath: socketPath,
		broker:     broker,
		stopChan:   make(chan struct{}),
	}, nil
}

// Start starts the IPC server
func (s *Server) Start(ctx context.Context) error {
	// Remove existing socket file
	if err := os.RemoveAll(s.socketPath); err != nil {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create socket directory if it doesn't exist
	socketDir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket listener: %w", err)
	}

	s.listener = listener

	// Set socket permissions
	if err := os.Chmod(s.socketPath, 0666); err != nil {
		log.Warn().
			Err(err).
			Str("socket_path", s.socketPath).
			Msg("Failed to set socket permissions")
	}

	log.Info().
		Str("socket_path", s.socketPath).
		Msg("IPC server started")

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptConnections(ctx)

	return nil
}

// Stop stops the IPC server
func (s *Server) Stop() error {
	var stopErr error
	s.stopOnce.Do(func() {
		log.Info().Msg("Stopping IPC server")

		// Signal stop
		close(s.stopChan)

		// Close listener
		if s.listener != nil {
			_ = s.listener.Close()
		}

		// Wait for goroutines to finish
		s.wg.Wait()

		// Remove socket file
		if err := os.RemoveAll(s.socketPath); err != nil {
			log.Warn().
				Err(err).
				Str("socket_path", s.socketPath).
				Msg("Failed to remove socket file")
		}

		log.Info().Msg("IPC server stopped")
	})
	return stopErr
}

// acceptConnections accepts and handles IPC connections
func (s *Server) acceptConnections(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
			// Set accept timeout
			if conn, ok := s.listener.(*net.UnixListener); ok {
				_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
			}

			conn, err := s.listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				// For other errors, check if we should continue or exit
				select {
				case <-ctx.Done():
					return
				case <-s.stopChan:
					return
				default:
					log.Error().
						Err(err).
						Msg("Failed to accept connection")
					return
				}
			}

			// Handle connection in goroutine
			s.wg.Add(1)
			go s.handleConnection(conn)
		}
	}
}

// handleConnection handles a single IPC connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	// Set connection timeout
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	log.Debug().
		Str("remote_addr", conn.RemoteAddr().String()).
		Msg("New IPC connection")

	// Read request
	decoder := json.NewDecoder(conn)
	var request Request
	if err := decoder.Decode(&request); err != nil {
		log.Error().
			Err(err).
			Msg("Failed to decode IPC request")
		s.sendErrorResponse(conn, "INVALID_REQUEST", "Failed to decode request")
		return
	}

	// Handle request
	response := s.handleRequest(&request)

	// Send response
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(response); err != nil {
		log.Error().
			Err(err).
			Msg("Failed to encode IPC response")
		return
	}

	log.Debug().
		Str("request_type", request.Type).
		Str("user_id", request.UserID).
		Bool("success", response.Success).
		Msg("IPC request handled")
}

// handleRequest handles different types of requests
func (s *Server) handleRequest(request *Request) *Response {
	switch request.Type {
	case "authenticate":
		return s.handleAuthenticate(request)
	case "check_session":
		return s.handleCheckSession(request)
	case "refresh_session":
		return s.handleRefreshSession(request)
	case "revoke_session":
		return s.handleRevokeSession(request)
	default:
		return &Response{
			Success:      false,
			ErrorCode:    "INVALID_REQUEST_TYPE",
			ErrorMessage: fmt.Sprintf("Unknown request type: %s", request.Type),
		}
	}
}

// handleAuthenticate handles authentication requests
func (s *Server) handleAuthenticate(request *Request) *Response {
	// Convert to auth request
	authRequest := &auth.AuthRequest{
		UserID:     request.UserID,
		SourceIP:   request.SourceIP,
		UserAgent:  request.UserAgent,
		TargetHost: request.TargetHost,
		LoginType:  request.LoginType,
		DeviceID:   request.DeviceID,
		SessionID:  request.SessionID,
		Timestamp:  time.Now(),
		Metadata:   request.Metadata,
	}

	// Call broker
	authResponse, err := s.broker.Authenticate(authRequest)
	if err != nil {
		log.Error().
			Err(err).
			Str("user_id", request.UserID).
			Msg("Authentication failed")

		return &Response{
			Success:      false,
			ErrorCode:    "AUTHENTICATION_FAILED",
			ErrorMessage: err.Error(),
		}
	}

	// Convert response
	response := &Response{
		Success:          authResponse.Success,
		UserID:           authResponse.UserID,
		Email:            authResponse.Email,
		Groups:           authResponse.Groups,
		SessionID:        authResponse.SessionID,
		DeviceCode:       authResponse.DeviceCode,
		DeviceURL:        authResponse.DeviceURL,
		QRCode:           authResponse.QRCode,
		ExpiresAt:        authResponse.ExpiresAt,
		SSHPublicKey:     authResponse.SSHPublicKey,
		RequiresDevice:   authResponse.RequiresDevice,
		RequiresApproval: authResponse.RequiresApproval,
		ErrorCode:        authResponse.ErrorCode,
		ErrorMessage:     authResponse.ErrorMessage,
		RiskScore:        authResponse.RiskScore,
		Metadata:         authResponse.Metadata,
	}

	// Add formatted instructions based on login type
	if authResponse.RequiresDevice {
		response.Instructions = s.formatInstructions(request.LoginType, authResponse.DeviceURL, authResponse.DeviceCode, authResponse.QRCode)
	}

	return response
}

// handleCheckSession handles session check requests
func (s *Server) handleCheckSession(request *Request) *Response {
	authResponse, err := s.broker.CheckSession(request.SessionID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", request.SessionID).
			Msg("Session check failed")

		return &Response{
			Success:      false,
			ErrorCode:    "SESSION_CHECK_FAILED",
			ErrorMessage: err.Error(),
		}
	}

	return &Response{
		Success:          authResponse.Success,
		UserID:           authResponse.UserID,
		Email:            authResponse.Email,
		Groups:           authResponse.Groups,
		SessionID:        authResponse.SessionID,
		ExpiresAt:        authResponse.ExpiresAt,
		SSHPublicKey:     authResponse.SSHPublicKey,
		RequiresDevice:   authResponse.RequiresDevice,
		RequiresApproval: authResponse.RequiresApproval,
		ErrorCode:        authResponse.ErrorCode,
		ErrorMessage:     authResponse.ErrorMessage,
		RiskScore:        authResponse.RiskScore,
		Metadata:         authResponse.Metadata,
	}
}

// handleRefreshSession handles session refresh requests
func (s *Server) handleRefreshSession(request *Request) *Response {
	authResponse, err := s.broker.RefreshSession(request.SessionID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", request.SessionID).
			Msg("Session refresh failed")

		return &Response{
			Success:      false,
			ErrorCode:    "SESSION_REFRESH_FAILED",
			ErrorMessage: err.Error(),
		}
	}

	return &Response{
		Success:      authResponse.Success,
		UserID:       authResponse.UserID,
		Email:        authResponse.Email,
		Groups:       authResponse.Groups,
		SessionID:    authResponse.SessionID,
		ExpiresAt:    authResponse.ExpiresAt,
		SSHPublicKey: authResponse.SSHPublicKey,
		ErrorCode:    authResponse.ErrorCode,
		ErrorMessage: authResponse.ErrorMessage,
		RiskScore:    authResponse.RiskScore,
		Metadata:     authResponse.Metadata,
	}
}

// handleRevokeSession handles session revocation requests
func (s *Server) handleRevokeSession(request *Request) *Response {
	err := s.broker.RevokeSession(request.SessionID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", request.SessionID).
			Msg("Session revocation failed")

		return &Response{
			Success:      false,
			ErrorCode:    "SESSION_REVOCATION_FAILED",
			ErrorMessage: err.Error(),
		}
	}

	return &Response{
		Success: true,
	}
}

// formatInstructions formats instructions based on login type
func (s *Server) formatInstructions(loginType, deviceURL, deviceCode, qrCode string) string {
	switch loginType {
	case "console":
		return auth.FormatConsoleInstructions(deviceURL, deviceCode, qrCode)
	case "gui":
		return auth.FormatGUIInstructions(deviceURL, deviceCode, qrCode)
	default: // ssh
		return auth.FormatDeviceInstructions(deviceURL, deviceCode, qrCode)
	}
}

// sendErrorResponse sends an error response
func (s *Server) sendErrorResponse(conn net.Conn, errorCode, errorMessage string) {
	response := &Response{
		Success:      false,
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(response); err != nil {
		log.Error().
			Err(err).
			Msg("Failed to send error response")
	}
}