package pam

/*
#cgo CFLAGS: -I${SRCDIR} -I/usr/include/security -Wall -Wextra
#cgo LDFLAGS: -lpam -ljson-c
#include "cgo_bridge.h"
*/
import "C"
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/scttfrdmn/oidc-pam/internal/brokerclient"
)

// PAMResultCode is a PAM result code.
//
// The values are taken from the PAM headers the module is compiled against
// rather than being copied by hand: they are not portable between
// implementations (Linux-PAM and OpenPAM disagree on almost everything past
// PAM_BUF_ERR), and a hand-copied value that libpam does not recognize turns a
// deliberate denial into an unknown error. PAMMaxTries was 24 before this was
// derived, which is not a Linux-PAM code at all.
type PAMResultCode int

const (
	PAMSuccess         PAMResultCode = C.PAM_SUCCESS
	PAMSystemError     PAMResultCode = C.PAM_SYSTEM_ERR
	PAMPermDenied      PAMResultCode = C.PAM_PERM_DENIED
	PAMAuthError       PAMResultCode = C.PAM_AUTH_ERR
	PAMAuthInfoUnavail PAMResultCode = C.PAM_AUTHINFO_UNAVAIL
	PAMMaxTries        PAMResultCode = C.PAM_MAXTRIES
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

// syslog priorities, as syslog.h defines them. The C bridge takes the raw int.
const (
	logErr    = 3 // LOG_ERR
	logNotice = 5 // LOG_NOTICE
	logInfo   = 6 // LOG_INFO
)

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

	resp, err := client.AuthenticateAndWait(ctx, &brokerclient.Request{
		UserID:     username,
		TargetHost: rhost,
		LoginType:  GetLoginType(service, tty),
		Metadata: map[string]interface{}{
			"service": service,
			"tty":     tty,
			"pid":     os.Getpid(),
		},
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

// LogMessage logs a message through the PAM logging system
func (p *PAMModule) LogMessage(priority int, message string) {
	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))

	C.log_pam_message_string(C.int(priority), cMessage)
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
