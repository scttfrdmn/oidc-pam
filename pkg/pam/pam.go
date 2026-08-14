package pam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scttfrdmn/oidc-pam/internal/brokerclient"
)

// PAMResultCode is a PAM result code.
//
// These are Linux-PAM's values. They are not portable — Linux-PAM and OpenPAM
// disagree on almost everything past PAM_BUF_ERR — and a value libpam does not
// recognize turns a deliberate denial into an unknown error, which is why
// PAMMaxTries being 24 (not a Linux-PAM code at all) was worth fixing in #118.
//
// They are written out here rather than read from <security/_pam_types.h> via
// cgo so that this package builds and tests on any platform (#141). The
// guarantee that they are correct is not lost: TestPAMResultCodesMatchHeaders in
// cmd/pam-module compares every constant below against the macro of the same
// name in the PAM headers the module is actually compiled against, and that test
// runs in the PAM (cgo) CI job. Change a value here and it fails.
type PAMResultCode int

const (
	PAMSuccess PAMResultCode = 0 // PAM_SUCCESS

	// PAMServiceError is "error in service module": the module and the broker
	// disagree about something, as opposed to the broker being unreachable
	// (PAMAuthInfoUnavail) or the user being refused (PAMAuthError). The module
	// returns it when a broker response does not fit its response buffer, so that
	// an operator can tell those three apart in auth.log (#162).
	PAMServiceError PAMResultCode = 3 // PAM_SERVICE_ERR

	PAMSystemError     PAMResultCode = 4  // PAM_SYSTEM_ERR
	PAMPermDenied      PAMResultCode = 6  // PAM_PERM_DENIED
	PAMAuthError       PAMResultCode = 7  // PAM_AUTH_ERR
	PAMAuthInfoUnavail PAMResultCode = 9  // PAM_AUTHINFO_UNAVAIL
	PAMMaxTries        PAMResultCode = 11 // PAM_MAXTRIES

	// PAMIgnore means "this module has no opinion". PAM does not count it
	// toward the stack's result, so unlike PAMSuccess it cannot short-circuit a
	// `sufficient` entry.
	PAMIgnore PAMResultCode = 25 // PAM_IGNORE
)

// PAMAuthFailure is returned by AuthenticateUser when the broker reports a
// failure. It carries both the human-readable message and the PAM result code
// so C-level callers can return the correct pam_sm_authenticate result.
type PAMAuthFailure struct {
	Code    PAMResultCode
	Message string
}

func (e *PAMAuthFailure) Error() string { return e.Message }

// ParseBrokerResponse unmarshals a JSON string from the broker into an
// AuthResponse. An empty string or invalid JSON returns an error.
func ParseBrokerResponse(jsonStr string) (*AuthResponse, error) {
	if jsonStr == "" {
		return nil, fmt.Errorf("empty response from broker")
	}
	var resp AuthResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse broker response: %w", err)
	}
	return &resp, nil
}

// errorCodeToPAMResult maps broker error codes to the most appropriate PAM
// result code. Unknown codes default to PAM_AUTH_ERR.
func errorCodeToPAMResult(errorCode string) PAMResultCode {
	switch errorCode {
	case "RATE_LIMIT_EXCEEDED", "TOO_MANY_CONCURRENT_AUTHS":
		return PAMMaxTries
	case "TOO_MANY_SESSIONS", "POLICY_DENIED", "NO_PROVIDER":
		return PAMPermDenied
	default:
		return PAMAuthError
	}
}

// syslog priorities, as syslog.h defines them.
const (
	logErr    = 3 // LOG_ERR
	logNotice = 5 // LOG_NOTICE
	logInfo   = 6 // LOG_INFO
)

// moduleSyslog is the connection LogMessage writes to, opened on first use.
//
// The C entry points log through pam_syslog(), which picks up the service name
// from the PAM handle. This package has no handle — it is reached from
// oidc-pam-helper, not from inside libpam — so it logs to LOG_AUTHPRIV under a
// fixed tag, which is where pam_syslog would have put it anyway.
var (
	syslogOnce   sync.Once
	syslogWriter *syslog.Writer
)

func moduleSyslog() *syslog.Writer {
	syslogOnce.Do(func() {
		// A failure here means syslogd is unreachable. There is nowhere left to
		// report that, and losing a log line must not fail an authentication, so
		// the writer stays nil and LogMessage becomes a no-op.
		syslogWriter, _ = syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_NOTICE, "pam_oidc")
	})
	return syslogWriter
}

// LogMessage logs a message to syslog at the given syslog.h priority.
func (p *PAMModule) LogMessage(priority int, message string) {
	w := moduleSyslog()
	if w == nil {
		return
	}

	var err error
	switch priority {
	case logErr:
		err = w.Err(message)
	case logInfo:
		err = w.Info(message)
	default:
		err = w.Notice(message)
	}
	_ = err // see moduleSyslog: a lost log line is not an authentication error.
}

// PAMModule represents the PAM module interface
type PAMModule struct {
	socketPath string
	debug      atomic.Bool

	// AuthTimeout bounds the wait for the user to complete the device flow.
	// Zero means brokerclient.DefaultAuthTimeout.
	AuthTimeout time.Duration
}

// NewPAMModule creates a new PAM module instance
func NewPAMModule(socketPath string, debug bool) *PAMModule {
	m := &PAMModule{socketPath: socketPath, AuthTimeout: brokerclient.DefaultAuthTimeout}
	m.debug.Store(debug)
	return m
}

// AuthenticateUser handles user authentication through the broker, waiting for
// the device authorization flow to complete.
//
// A nil return means the user authenticated. A *PAMAuthFailure means the login
// was refused — including when the user simply never completed the device flow —
// and carries the PAM result code the caller should return. Any other error means
// the broker could not be reached or understood, which is PAM_AUTHINFO_UNAVAIL
// territory: no opinion, rather than a grant.
func (p *PAMModule) AuthenticateUser(username, service, rhost, tty string) error {
	return p.AuthenticateUserContext(context.Background(), username, service, rhost, tty)
}

// AuthenticateUserContext is AuthenticateUser with a caller-supplied context;
// cancelling it abandons the wait for device authorization.
func (p *PAMModule) AuthenticateUserContext(ctx context.Context, username, service, rhost, tty string) error {
	client := brokerclient.New(p.socketPath)

	// Surface the verification URL and user code. This is the only chance the
	// user gets to learn where to authenticate, so it goes to syslog at
	// LOG_NOTICE regardless of debug mode.
	client.OnDeviceFlow = func(resp *brokerclient.Response) {
		if resp.Instructions != "" {
			p.LogMessage(logNotice, resp.Instructions)
		}
		if resp.DeviceURL != "" {
			p.LogMessage(logNotice, fmt.Sprintf("OIDC authentication: visit %s", resp.DeviceURL))
		}
		if resp.DeviceCode != "" {
			p.LogMessage(logNotice, fmt.Sprintf("OIDC authentication: enter code %s", resp.DeviceCode))
		}
	}

	timeout := p.AuthTimeout
	if timeout <= 0 {
		timeout = brokerclient.DefaultAuthTimeout
	}

	// (#169) rhost is PAM_RHOST: where the login is coming from, so it is the
	// request's source_ip — the input to every network policy, the IP allowlists
	// and the location history. target_host is this machine. Sending rhost as
	// target_host, and nothing as source_ip, is what made require_private_network
	// refuse every login. The unabridged rhost goes in metadata for the audit
	// trail, since source_ip carries only an address.
	metadata := map[string]interface{}{
		"service": service,
		"tty":     tty,
		"pid":     os.Getpid(),
	}
	if rhost != "" {
		metadata["rhost"] = rhost
	}

	resp, err := client.AuthenticateAndWait(ctx, &brokerclient.Request{
		UserID:     username,
		SourceIP:   brokerclient.SourceIPFromRHost(rhost),
		TargetHost: brokerclient.ThisHost(),
		LoginType:  GetLoginType(service, tty),
		Metadata:   metadata,
	}, timeout)
	if err != nil {
		return p.authFailure(err)
	}

	if resp.Instructions != "" {
		p.LogMessage(logInfo, resp.Instructions)
	}
	return nil
}

// authFailure turns a brokerclient error into the error contract described on
// AuthenticateUser, logging it on the way out.
func (p *PAMModule) authFailure(err error) error {
	var denial *brokerclient.DenialError
	if errors.As(err, &denial) {
		msg := denial.Message
		if msg == "" {
			msg = "authentication failed"
		}
		if p.debug.Load() && denial.ErrorCode != "" {
			p.LogMessage(logErr, fmt.Sprintf("OIDC authentication failed: %s (%s)", msg, denial.ErrorCode))
		} else {
			p.LogMessage(logErr, fmt.Sprintf("OIDC authentication failed: %s", msg))
		}
		return &PAMAuthFailure{
			Code:    errorCodeToPAMResult(denial.ErrorCode),
			Message: msg,
		}
	}

	var timeout *brokerclient.TimeoutError
	if errors.As(err, &timeout) {
		p.LogMessage(logErr, fmt.Sprintf("OIDC authentication failed: %s", timeout))
		return &PAMAuthFailure{
			Code:    PAMAuthError,
			Message: timeout.Error(),
		}
	}

	// Could not reach an opinion: leave it to the caller to translate into
	// PAM_AUTHINFO_UNAVAIL rather than reporting a denial we did not observe.
	p.LogMessage(logErr, fmt.Sprintf("OIDC authentication unavailable: %v", err))
	return err
}

// GetSocketPath returns the configured socket path
func (p *PAMModule) GetSocketPath() string {
	return p.socketPath
}

// IsDebugEnabled returns whether debug mode is enabled
func (p *PAMModule) IsDebugEnabled() bool {
	return p.debug.Load()
}

// SetDebug enables or disables debug mode
func (p *PAMModule) SetDebug(enabled bool) {
	p.debug.Store(enabled)
}
