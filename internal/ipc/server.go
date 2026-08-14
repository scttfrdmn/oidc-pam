package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/auth"
)

// Server handles IPC communication with PAM modules
type Server struct {
	socketPath      string
	socketMode      os.FileMode
	socketGroup     string
	requirePeerAuth bool
	broker          *auth.Broker
	rateLimiter     *RateLimiter
	listener        net.Listener
	stopChan        chan struct{}
	wg              sync.WaitGroup
	stopOnce        sync.Once
	connSem         chan struct{} // bounds concurrent in-flight connections (L-4)

	// peerVerifier, when non-nil, replaces the platform peer-credential check. See
	// verifyPeer: it exists so this package's socket-level tests can run as an
	// ordinary user, and is nil in every Server the constructor builds (#189).
	peerVerifier func(conn net.Conn) (uid uint32, err error)
}

// maxConcurrentConnections caps the number of simultaneously handled IPC
// connections so a peer cannot exhaust goroutines/FDs by opening many at once.
const maxConcurrentConnections = 128

// acceptBackoffMin and acceptBackoffMax bound the pause between retries after a
// failed accept(2). See nextAcceptBackoff.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = 1 * time.Second
)

// Request represents a request from PAM module
type Request struct {
	Type       string                 `json:"type"`
	UserID     string                 `json:"user_id"`
	SourceIP   string                 `json:"source_ip"`
	UserAgent  string                 `json:"user_agent"`
	TargetHost string                 `json:"target_host"`
	LoginType  string                 `json:"login_type"`
	DeviceID   string                 `json:"device_id"`
	SessionID  string                 `json:"session_id"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// Response represents a response to PAM module.
//
// Every field here costs part of maxResponseSize, so nothing goes in twice. There
// used to be a qr_code field alongside Instructions, which already embeds the same
// ASCII art: no client ever read it, and the two copies together put an ordinary
// device-flow response ~20 bytes under the module's 8 KiB buffer (#162).
type Response struct {
	Success          bool                   `json:"success"`
	UserID           string                 `json:"user_id"`
	Email            string                 `json:"email"`
	Groups           []string               `json:"groups"`
	SessionID        string                 `json:"session_id"`
	DeviceCode       string                 `json:"device_code"`
	DeviceURL        string                 `json:"device_url"`
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

// NewServer creates a new IPC server. maxRequestsPerMinute and
// maxConcurrentAuths configure per-account rate limiting and the global
// concurrent auth cap respectively. Values <= 0 disable that limit.
func NewServer(socketPath string, broker *auth.Broker, socketMode os.FileMode, socketGroup string, requirePeerAuth bool, maxRequestsPerMinute, maxConcurrentAuths int) (*Server, error) {
	return &Server{
		socketPath:      socketPath,
		socketMode:      socketMode,
		socketGroup:     socketGroup,
		requirePeerAuth: requirePeerAuth,
		broker:          broker,
		rateLimiter:     NewRateLimiter(maxRequestsPerMinute, maxConcurrentAuths),
		stopChan:        make(chan struct{}),
		connSem:         make(chan struct{}, maxConcurrentConnections),
	}, nil
}

// Start starts the IPC server
func (s *Server) Start(ctx context.Context) error {
	// Create socket directory if it doesn't exist
	socketDir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(socketDir, 0750); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Refuse to serve under a directory another account can write to. MkdirAll
	// above is a no-op when the directory already exists, so an installer that
	// created it 0755 and chowned it to an unprivileged account leaves that mode
	// and owner in place — and write permission on the directory is enough to
	// unlink this socket and bind an impostor at the same path (#200).
	if err := verifySocketDirTrusted(socketDir); err != nil {
		return fmt.Errorf("refusing to listen on %s: %w", s.socketPath, err)
	}

	// Remove existing socket file
	if err := os.RemoveAll(s.socketPath); err != nil {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Set umask to 0117 before creating the socket so it is created with
	// permissions 0660 (owner+group rw) from the start, closing the window
	// between creation and the os.Chmod call below.
	oldMask := syscall.Umask(0117)
	listener, err := net.Listen("unix", s.socketPath)
	syscall.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket listener: %w", err)
	}

	s.listener = listener

	// Set socket permissions. Fail closed: if we cannot enforce the intended
	// mode we must not keep serving on a socket with unknown permissions.
	if err := os.Chmod(s.socketPath, s.socketMode); err != nil {
		_ = listener.Close()
		return fmt.Errorf("failed to set socket permissions on %s: %w", s.socketPath, err)
	}

	// Set socket group ownership if configured
	if s.socketGroup != "" {
		grp, err := user.LookupGroup(s.socketGroup)
		if err != nil {
			return fmt.Errorf("failed to look up socket group %q: %w", s.socketGroup, err)
		}
		gid, err := strconv.Atoi(grp.Gid)
		if err != nil {
			return fmt.Errorf("failed to parse group ID for %q: %w", s.socketGroup, err)
		}
		if err := os.Chown(s.socketPath, -1, gid); err != nil {
			return fmt.Errorf("failed to set socket group ownership: %w", err)
		}
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

		// Stop rate limiter cleanup goroutine
		if s.rateLimiter != nil {
			s.rateLimiter.Stop()
		}

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

	backoff := time.Duration(0)

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
					backoff = 0
					continue
				}

				// A deliberate shutdown is the only reason to stop accepting.
				select {
				case <-ctx.Done():
					return
				case <-s.stopChan:
					return
				default:
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}

				// Everything else is transient and must not take the broker's
				// socket out of service. accept(2) fails with EMFILE/ENFILE when
				// the descriptor table is full, ECONNABORTED when the peer goes
				// away between the SYN and the accept, and EINTR on a signal —
				// none of which say anything about the listener. This loop used to
				// return here, so the first such error left a process that systemd
				// still saw as healthy, with Restart=always never firing, that
				// accepted no connection again for the rest of its life: on a host
				// wired with configs/pam/ssh, every login denied until an operator
				// noticed and restarted it by hand (#216).
				backoff = nextAcceptBackoff(backoff)
				event := log.Error()
				if isTransientAcceptError(err) {
					event = log.Warn()
				}
				event.
					Err(err).
					Dur("retry_in", backoff).
					Msg("Failed to accept connection; retrying")

				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return
				case <-s.stopChan:
					return
				}
				continue
			}
			backoff = 0

			// Bound concurrent connections (L-4): if at capacity, reject rather
			// than spawning an unbounded number of handler goroutines.
			select {
			case s.connSem <- struct{}{}:
			default:
				log.Warn().Msg("Connection rejected: at maximum concurrent connections")
				// This write happens on the accept loop itself, not in a handler, so
				// it gets a deadline of its own: a peer that connects, fills the
				// socket buffer and never reads must not be able to park the loop
				// that every other login depends on (#216).
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				s.sendErrorResponse(conn, "SERVER_BUSY", "Server at capacity, try again")
				_ = conn.Close()
				continue
			}

			// Handle connection in goroutine
			s.wg.Add(1)
			go s.handleConnection(conn)
		}
	}
}

// nextAcceptBackoff returns how long to pause after a failed accept(2).
//
// The pause exists so that a failure which is transient but not instantly cleared
// — a full descriptor table, most obviously — is retried without spinning a core
// and without filling the journal. It is capped so the broker never stays deaf for
// longer than a second once the condition clears.
func nextAcceptBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return acceptBackoffMin
	}
	if next := current * 2; next < acceptBackoffMax {
		return next
	}
	return acceptBackoffMax
}

// isTransientAcceptError reports whether err is one of the accept(2) failures with
// a known, self-clearing cause. It only chooses the log level: every error other
// than a closed listener is retried either way, because a broker that has stopped
// accepting connections is indistinguishable from a broker that is down, except
// that nothing restarts it.
func isTransientAcceptError(err error) bool {
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.EAGAIN)
}

// verifyPeer identifies the process on the other end of conn and rejects any peer
// the broker must not serve. It returns the peer's uid, which is what malformed
// requests are charged against.
//
// The indirection through s.peerVerifier is a test seam, and it is here because of
// what its absence cost. verifyPeerCredentials is a Linux-only kernel lookup that
// requires the peer to be uid 0, so every test that speaks to the socket had to skip
// unless the suite was running as root on Linux — which CI is not. The one test that
// asserted the socket rate-limits a flood therefore skipped on every run the project
// has ever made, was green because it was absent, and hid an ordering that meant no
// malformed request was ever counted (#189).
//
// The field is unexported and left nil by NewServer, so no production path can
// substitute the check: a Server that was never told otherwise fails closed through
// verifyPeerCredentials, which on a non-Linux host refuses every connection.
func (s *Server) verifyPeer(conn net.Conn) (uint32, error) {
	if s.peerVerifier != nil {
		return s.peerVerifier(conn)
	}
	return verifyPeerCredentials(conn)
}

// rejectMalformed answers a request that no handler will ever see — one that would
// not decode, or that validateRequest refused — and charges it against the sending
// peer's malformed-request budget. Once that budget is spent the peer is told
// RATE_LIMIT_EXCEEDED instead, and its next well-formed request is unaffected.
//
// The budget is consulted after the request has been recognised as malformed rather
// than before it is read, and that ordering is deliberate: at the earlier point a
// valid request is indistinguishable from a malformed one, and every peer shares
// this bucket (every peer's uid is 0), so gating the read on it would let a flood of
// garbage refuse real logins — the failure #160 removed, reintroduced from the other
// side. What it does bound is how long a peer can keep being answered, and it puts a
// flood in the journal where an operator can see it, instead of leaving malformed
// requests uncounted forever (#189).
func (s *Server) rejectMalformed(conn net.Conn, peerUID uint32, errorCode, errorMessage string) {
	if s.rateLimiter.Allow(ClassMalformed, strconv.FormatUint(uint64(peerUID), 10)) {
		s.sendErrorResponse(conn, errorCode, errorMessage)
		return
	}

	log.Warn().
		Uint32("peer_uid", peerUID).
		Msg("Malformed-request budget exhausted for peer; refusing further malformed requests")
	s.sendErrorResponse(conn, "RATE_LIMIT_EXCEEDED", clientErrorMessage("RATE_LIMIT_EXCEEDED"))
}

// handleConnection handles a single IPC connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() { <-s.connSem }() // release the concurrency slot (L-4)
	defer func() { _ = conn.Close() }()

	// Set the connection timeout before anything reads from or writes to conn, so
	// that no path through this function — including the rejection below, which
	// writes to a peer that may never read — can block a handler goroutine
	// indefinitely. This deadline is only as good as the descriptor's O_NONBLOCK
	// flag: see the comment on withSocketFD for how a peer-credential lookup used
	// to clear it and void every deadline on the connection (#216).
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Verify peer is root — PAM modules always run as root
	peerUID, err := s.verifyPeer(conn)
	if err != nil {
		log.Warn().Err(err).Msg("Rejected IPC connection from non-root peer")
		s.sendErrorResponse(conn, "PERMISSION_DENIED", "Connection rejected")
		return
	}

	// Verify peer credentials if required
	if s.requirePeerAuth {
		uid, gid, err := getPeerCredentials(conn)
		if err != nil {
			log.Warn().
				Err(err).
				Msg("Failed to get peer credentials, rejecting connection")
			s.sendErrorResponse(conn, "PEER_AUTH_FAILED", "Failed to verify peer credentials")
			return
		}
		if uid != 0 {
			log.Warn().
				Uint32("uid", uid).
				Uint32("gid", gid).
				Msg("Connection from non-root process rejected")
			s.sendErrorResponse(conn, "PEER_AUTH_DENIED", "Only root processes are allowed to connect")
			return
		}
		log.Debug().
			Uint32("uid", uid).
			Uint32("gid", gid).
			Msg("Peer credentials verified")
	}

	// Rate limiting for requests that reach a handler happens in handleRequest, once
	// the request has been decoded and validated: those limits are keyed on the
	// account a request names, which is not known before then. It used to happen
	// here, keyed on the peer uid — a value that can only ever be 0, so the whole
	// host shared one bucket (#160).
	//
	// Requests that reach no handler are charged here instead, to the peer that sent
	// them: see rejectMalformed. They used to be charged to nothing at all, so a
	// local peer could hold the broker in accept, read, decode and validate as fast
	// as it could write, and the only limit that exists to bound that work never saw
	// one of them (#189).

	log.Debug().
		Str("remote_addr", conn.RemoteAddr().String()).
		Msg("New IPC connection")

	// Read request with size limit to prevent memory exhaustion
	limitedReader := io.LimitReader(conn, maxRequestSize)
	decoder := json.NewDecoder(limitedReader)
	var request Request
	if err := decoder.Decode(&request); err != nil {
		log.Error().
			Err(err).
			Msg("Failed to decode IPC request")
		s.rejectMalformed(conn, peerUID, "INVALID_REQUEST", "Failed to decode request")
		return
	}

	// Validate request fields
	if err := validateRequest(&request); err != nil {
		log.Warn().
			Err(err).
			Str("request_type", request.Type).
			Msg("Invalid IPC request")
		s.rejectMalformed(conn, peerUID, "INVALID_REQUEST", clientErrorMessage("INVALID_REQUEST"))
		return
	}

	// Handle request
	response := s.handleRequest(&request)

	// Send response
	s.writeResponse(conn, response)

	log.Debug().
		Str("request_type", request.Type).
		Str("user_id", request.UserID).
		Bool("success", responseSucceeded(response)).
		Msg("IPC request handled")
}

// responseSucceeded reports whether a handler's response carries a result rather
// than a failure, so the connection handler can log the outcome without knowing
// which shape it is sending.
func responseSucceeded(response any) bool {
	switch r := response.(type) {
	case *Response:
		return r.Success
	case interface{ Err() error }: // the adminapi responses
		return r.Err() == nil
	default:
		return true
	}
}

// handleRequest handles different types of requests.
//
// It returns `any` rather than *Response because the administrative requests
// (`status`, `sessions_list`, `keys_list`) answer with their own shapes, defined
// in internal/adminapi: a session listing does not fit into the fields of an
// authentication response.
func (s *Server) handleRequest(request *Request) any {
	if class, limited := rateClassFor(request.Type); limited {
		if !s.rateLimiter.Allow(class, request.UserID) {
			log.Warn().
				Str("request_type", request.Type).
				Str("user_id", request.UserID).
				Msg("Rate limit exceeded for account")
			return &Response{
				Success:      false,
				ErrorCode:    "RATE_LIMIT_EXCEEDED",
				ErrorMessage: clientErrorMessage("RATE_LIMIT_EXCEEDED"),
			}
		}
	}

	switch request.Type {
	case "authenticate":
		if !s.rateLimiter.AcquireAuth() {
			log.Warn().Msg("Concurrent auth limit reached")
			return &Response{
				Success:      false,
				ErrorCode:    "TOO_MANY_CONCURRENT_AUTHS",
				ErrorMessage: clientErrorMessage("TOO_MANY_CONCURRENT_AUTHS"),
			}
		}
		defer s.rateLimiter.ReleaseAuth()
		return s.handleAuthenticate(request)
	case "check_session":
		return s.handleCheckSession(request)
	case "refresh_session":
		return s.handleRefreshSession(request)
	case "revoke_session":
		return s.handleRevokeSession(request)
	case "status":
		return s.handleStatus()
	case "sessions_list":
		return s.handleSessionsList()
	case "keys_list":
		return s.handleKeysList()
	default:
		log.Warn().
			Str("request_type", request.Type).
			Msg("Unknown request type")
		return &Response{
			Success:      false,
			ErrorCode:    "INVALID_REQUEST_TYPE",
			ErrorMessage: clientErrorMessage("INVALID_REQUEST_TYPE"),
		}
	}
}

// rateClassFor maps a request type to the budget it is charged against, and
// reports whether it is charged at all.
//
// The administrative reads (status, sessions_list, keys_list) are not: they name no
// account, so every one of them would share a single bucket, which is the shape of
// the bug this replaced. They are already bounded by being root-only on a
// local socket, and an operator running `oidc-admin` in a loop is not a threat
// model — whereas an operator whose `oidc-admin status` is refused while they are
// diagnosing an incident is a real cost.
func rateClassFor(requestType string) (RateClass, bool) {
	switch requestType {
	case "authenticate":
		return ClassAuthenticate, true
	case "check_session", "refresh_session", "revoke_session":
		return ClassSession, true
	default:
		return "", false
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
			ErrorMessage: clientErrorMessage("AUTHENTICATION_FAILED"),
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
		s.setDeviceInstructions(response, request.LoginType, authResponse.QRCode)
	}

	return response
}

// handleCheckSession handles session check requests
func (s *Server) handleCheckSession(request *Request) *Response {
	authResponse, err := s.broker.CheckSession(request.SessionID, request.UserID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", request.SessionID).
			Msg("Session check failed")

		return &Response{
			Success:      false,
			ErrorCode:    "SESSION_CHECK_FAILED",
			ErrorMessage: clientErrorMessage("SESSION_CHECK_FAILED"),
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
	authResponse, err := s.broker.RefreshSession(request.SessionID, request.UserID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", request.SessionID).
			Msg("Session refresh failed")

		return &Response{
			Success:      false,
			ErrorCode:    "SESSION_REFRESH_FAILED",
			ErrorMessage: clientErrorMessage("SESSION_REFRESH_FAILED"),
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
	err := s.broker.RevokeSession(request.SessionID, request.UserID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", request.SessionID).
			Msg("Session revocation failed")

		return &Response{
			Success:      false,
			ErrorCode:    "SESSION_REVOCATION_FAILED",
			ErrorMessage: clientErrorMessage("SESSION_REVOCATION_FAILED"),
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
	s.writeResponse(conn, &Response{
		Success:      false,
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
	})
}
