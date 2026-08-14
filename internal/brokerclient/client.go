// Package brokerclient speaks the broker's Unix-socket IPC protocol from Go.
//
// It exists so the device authorization flow has one Go implementation that can
// actually be tested: the PAM module's copy is in C, unbuildable on a developer
// laptop without PAM headers, and reachable only through cgo. Everything here is
// standard library, so `go test` covers it everywhere.
//
// The request and response types are deliberately a local copy of the ones in
// internal/ipc rather than an import: internal/ipc pulls in the whole broker
// (pkg/auth and its OIDC, policy and audit dependencies), which has no business
// being linked into a client that runs as part of a login.
package brokerclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	// DefaultDialTimeout bounds connecting to the broker socket.
	DefaultDialTimeout = 5 * time.Second

	// DefaultRequestTimeout bounds a single request/response exchange.
	DefaultRequestTimeout = 30 * time.Second

	// DefaultAuthTimeout bounds the wait for the user to complete the device
	// flow. It matches DEFAULT_AUTH_TIMEOUT in pkg/pam/cgo_bridge.h and stays
	// below sshd's default LoginGraceTime of 120s.
	DefaultAuthTimeout = 90 * time.Second

	// Bounds on the poll interval the broker asks for in
	// metadata.polling_interval. The broker already clamps what it sends to
	// [5, 3600]s; these keep a missing or malformed value from becoming a busy
	// loop or an unbounded wait. They match the C module's bounds.
	DefaultPollInterval = 5 * time.Second
	MinPollInterval     = 1 * time.Second
	MaxPollInterval     = 60 * time.Second
)

// Request is an IPC request. It mirrors ipc.Request.
//
// SourceIP is where the login came from and TargetHost is where it is going: this
// machine. (#169) Both clients used to send PAM_RHOST — the address the user is
// connecting *from* — as TargetHost and send no SourceIP at all, which left every
// audit record naming the client as the host being logged into and every policy
// that reads source_ip evaluating the empty string. Use SourceIPFromRHost and
// ThisHost rather than filling them in by hand.
type Request struct {
	Type       string                 `json:"type"`
	UserID     string                 `json:"user_id,omitempty"`
	SourceIP   string                 `json:"source_ip,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	TargetHost string                 `json:"target_host,omitempty"`
	LoginType  string                 `json:"login_type,omitempty"`
	DeviceID   string                 `json:"device_id,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// MaxSourceIPLen is the wire contract's bound on source_ip: an IPv6 literal with
// a zone. The broker refuses anything longer.
const MaxSourceIPLen = 45

// SourceIPFromRHost derives the request's source_ip from PAM's PAM_RHOST.
//
// source_ip carries an address or nothing, so an rhost that is a hostname — which
// is what sshd supplies with UseDNS on — yields "". Passing the hostname through
// would be worse than omitting it: a policy would evaluate a string that is not a
// location, and no downstream check re-resolves it. The unabridged rhost still
// reaches the broker in metadata.rhost, where it is audit context and nothing
// consults it for a decision.
//
// An empty result therefore means "this login has no address the broker can act
// on", which is a state the broker handles deliberately
// (network_requirements.unknown_source_ip) rather than one it infers.
func SourceIPFromRHost(rhost string) string {
	if rhost == "" || len(rhost) > MaxSourceIPLen {
		return ""
	}
	// A zone ("fe80::1%eth0") names an interface on the sending host, and
	// net.ParseIP rejects it, so it is validated without and returned with.
	addr := rhost
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	if net.ParseIP(addr) == nil {
		return ""
	}
	return rhost
}

// ThisHost is the request's target_host: the host being logged into. A hostname
// that cannot be determined is omitted rather than guessed, since a wrong one
// selects the wrong per-resource policy.
func ThisHost() string {
	name, err := os.Hostname()
	if err != nil || len(name) > 253 {
		return ""
	}
	return name
}

// Response is an IPC response. It mirrors ipc.Response.
type Response struct {
	Success          bool                   `json:"success"`
	UserID           string                 `json:"user_id,omitempty"`
	Email            string                 `json:"email,omitempty"`
	Groups           []string               `json:"groups,omitempty"`
	SessionID        string                 `json:"session_id,omitempty"`
	DeviceCode       string                 `json:"device_code,omitempty"`
	DeviceURL        string                 `json:"device_url,omitempty"`
	ExpiresAt        time.Time              `json:"expires_at,omitempty"`
	SSHPublicKey     string                 `json:"ssh_public_key,omitempty"`
	RequiresDevice   bool                   `json:"requires_device,omitempty"`
	RequiresApproval bool                   `json:"requires_approval,omitempty"`
	ErrorCode        string                 `json:"error_code,omitempty"`
	ErrorMessage     string                 `json:"error_message,omitempty"`
	Instructions     string                 `json:"instructions,omitempty"`
	RiskScore        int                    `json:"risk_score,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// DenialError reports that the broker refused the authentication. It is a
// decision, not a failure to obtain one: callers must treat it as a denial.
//
// A poll answered with SESSION_NOT_FOUND, SESSION_EXPIRED or FORBIDDEN is also a
// denial, because the broker deletes the session when identity binding fails,
// when require_groups rejects the user, when polling the IdP fails, and when the
// session expires.
type DenialError struct {
	ErrorCode string
	Message   string
}

func (e *DenialError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = "authentication denied by broker"
	}
	if e.ErrorCode == "" {
		return msg
	}
	return fmt.Sprintf("%s (%s)", msg, e.ErrorCode)
}

// TimeoutError reports that the user did not complete the device flow in time.
// Like DenialError it is a denial: an unfinished flow is never a success.
type TimeoutError struct {
	Waited time.Duration
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("device authorization not completed within %s", e.Waited)
}

// Client talks to the broker over its Unix socket.
//
// The broker serves exactly one request per connection and then closes it, so
// each call here dials its own connection.
type Client struct {
	SocketPath string

	// DialTimeout bounds connecting; RequestTimeout bounds one exchange.
	DialTimeout    time.Duration
	RequestTimeout time.Duration

	// OnDeviceFlow, if set, is called once with the initiation response when the
	// broker asks for device authorization — that is where the verification URL
	// and user code are shown to the user.
	OnDeviceFlow func(*Response)

	// now and sleep are injectable so the polling loop can be tested without
	// spending real time.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// New returns a Client for the broker listening on socketPath.
func New(socketPath string) *Client {
	return &Client{
		SocketPath:     socketPath,
		DialTimeout:    DefaultDialTimeout,
		RequestTimeout: DefaultRequestTimeout,
	}
}

func (c *Client) clock() func() time.Time {
	if c.now != nil {
		return c.now
	}
	return time.Now
}

func (c *Client) wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}

	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Do performs one request/response exchange on its own connection.
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	dialTimeout := c.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = DefaultDialTimeout
	}
	requestTimeout := c.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = DefaultRequestTimeout
	}

	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to broker at %s: %w", c.SocketPath, err)
	}
	defer func() { _ = conn.Close() }()

	// Real clock, not c.clock(): this is an OS-level deadline on a real socket.
	// c.clock() is the virtual clock the polling loop is measured against.
	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return nil, fmt.Errorf("set broker connection deadline: %w", err)
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("send %s request: %w", req.Type, err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response to %s request: %w", req.Type, err)
	}

	return &resp, nil
}

// Authenticate starts an authentication and returns the broker's first
// response. A response with RequiresDevice set means the device flow has begun
// and is *not* a successful authentication — see AuthenticateAndWait.
func (c *Client) Authenticate(ctx context.Context, req *Request) (*Response, error) {
	authRequest := *req
	authRequest.Type = "authenticate"
	return c.Do(ctx, &authRequest)
}

// CheckSession asks the broker for the state of a session. userID is required:
// the broker compares it against the session owner and answers FORBIDDEN when
// they differ.
func (c *Client) CheckSession(ctx context.Context, sessionID, userID string) (*Response, error) {
	return c.Do(ctx, &Request{
		Type:      "check_session",
		SessionID: sessionID,
		UserID:    userID,
	})
}

// AuthenticateAndWait authenticates and, if the broker starts a device flow,
// polls until it completes or timeout expires.
//
// It returns the granting response, or an error. The error is a *DenialError or
// *TimeoutError when the broker (or the clock) refused the login, and an
// ordinary error when the broker could not be reached or understood — callers
// that map to PAM codes should return PAM_AUTHINFO_UNAVAIL only for the latter.
//
// A response is treated as a grant only when Success is set *and* RequiresDevice
// is not: the broker reports Success together with RequiresDevice while the flow
// is merely pending, and identity binding and require_groups are enforced after
// that point.
func (c *Client) AuthenticateAndWait(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	if timeout <= 0 {
		timeout = DefaultAuthTimeout
	}

	resp, err := c.Authenticate(ctx, req)
	if err != nil {
		return nil, err
	}

	if !resp.RequiresDevice {
		if !resp.Success {
			return nil, &DenialError{ErrorCode: resp.ErrorCode, Message: resp.ErrorMessage}
		}
		return resp, nil
	}
	if !resp.Success {
		// A refusal that also happens to set requires_device is still a refusal.
		return nil, &DenialError{ErrorCode: resp.ErrorCode, Message: resp.ErrorMessage}
	}
	if resp.SessionID == "" {
		return nil, fmt.Errorf("broker requires device authorization but returned no session_id")
	}

	if c.OnDeviceFlow != nil {
		c.OnDeviceFlow(resp)
	}

	interval := pollInterval(resp)
	now := c.clock()
	start := now()
	deadline := start.Add(timeout)
	userID := req.UserID
	sessionID := resp.SessionID

	for {
		remaining := deadline.Sub(now())
		delay := interval
		if remaining < delay {
			delay = remaining
		}
		// Wait before polling: the broker has only just issued the device code,
		// so an immediate poll can only report "pending".
		if err := c.wait(ctx, delay); err != nil {
			return nil, err
		}

		resp, err := c.CheckSession(ctx, sessionID, userID)
		if err != nil {
			return nil, err
		}
		if !resp.Success {
			return nil, &DenialError{ErrorCode: resp.ErrorCode, Message: resp.ErrorMessage}
		}
		if !resp.RequiresDevice {
			return resp, nil
		}

		if !now().Before(deadline) {
			return nil, &TimeoutError{Waited: timeout}
		}
	}
}

// pollInterval reads metadata.polling_interval (seconds) from a response,
// clamped to [MinPollInterval, MaxPollInterval].
func pollInterval(resp *Response) time.Duration {
	raw, ok := resp.Metadata["polling_interval"]
	if !ok {
		return DefaultPollInterval
	}

	var seconds float64
	switch v := raw.(type) {
	case float64: // JSON numbers
		seconds = v
	case int:
		seconds = float64(v)
	default:
		return DefaultPollInterval
	}

	interval := time.Duration(seconds * float64(time.Second))
	if interval < MinPollInterval {
		return MinPollInterval
	}
	if interval > MaxPollInterval {
		return MaxPollInterval
	}
	return interval
}
