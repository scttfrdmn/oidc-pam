package pam

/*
#cgo CFLAGS: -I${SRCDIR} -I/usr/include/security
#cgo LDFLAGS: -lpam -ljson-c
#include "cgo_bridge.h"
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"unsafe"
)

// PAMResultCode mirrors the PAM result code constants from
// /usr/include/security/_pam_types.h.
type PAMResultCode int

const (
	PAMSuccess     PAMResultCode = 0  // PAM_SUCCESS
	PAMSystemError PAMResultCode = 4  // PAM_SYSTEM_ERR
	PAMPermDenied  PAMResultCode = 6  // PAM_PERM_DENIED
	PAMAuthError   PAMResultCode = 7  // PAM_AUTH_ERR
	PAMMaxTries    PAMResultCode = 24 // PAM_MAXTRIES
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

// PAMModule represents the PAM module interface
type PAMModule struct {
	socketPath string
	debug      atomic.Bool
}

// NewPAMModule creates a new PAM module instance
func NewPAMModule(socketPath string, debug bool) *PAMModule {
	m := &PAMModule{socketPath: socketPath}
	m.debug.Store(debug)
	return m
}

// AuthenticateUser handles user authentication through the broker
func (p *PAMModule) AuthenticateUser(username, service, rhost, tty string) error {
	// Convert Go strings to C strings
	cUsername := C.CString(username)
	cService := C.CString(service)
	cRhost := C.CString(rhost)
	cTTY := C.CString(tty)
	cSocketPath := C.CString(p.socketPath)

	// Ensure C strings are freed
	defer C.free(unsafe.Pointer(cUsername))
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cRhost))
	defer C.free(unsafe.Pointer(cTTY))
	defer C.free(unsafe.Pointer(cSocketPath))

	// Connect to broker
	sock := C.connect_to_broker(cSocketPath)
	if sock == -1 {
		return fmt.Errorf("failed to connect to authentication broker")
	}
	defer C.close(sock)

	// Send authentication request
	if C.send_auth_request(sock, cUsername, cService, cRhost, cTTY) != 0 {
		return fmt.Errorf("failed to send authentication request")
	}

	// Receive and parse the broker response
	var response [4096]C.char
	if C.receive_auth_response(sock, &response[0], 4096) != 0 {
		return fmt.Errorf("failed to receive authentication response")
	}

	authResp, err := ParseBrokerResponse(C.GoString(&response[0]))
	if err != nil {
		return fmt.Errorf("failed to parse broker response: %w", err)
	}

	// When device flow is required, surface the device URL and user code so
	// the user knows where to authenticate. Messages are sent to syslog and
	// (where supported) to the PAM conversation.
	if authResp.RequiresDevice {
		if authResp.DeviceURL != "" {
			p.LogMessage(5 /* LOG_NOTICE */, fmt.Sprintf("OIDC authentication: visit %s", authResp.DeviceURL))
		}
		if authResp.DeviceCode != "" {
			p.LogMessage(5 /* LOG_NOTICE */, fmt.Sprintf("OIDC authentication: enter code %s", authResp.DeviceCode))
		}
		// Device flow initiated; the PAM stack will poll via check_session.
		return nil
	}

	if !authResp.Success {
		msg := authResp.ErrorMessage
		if msg == "" {
			msg = "authentication failed"
		}
		// Log the error so it appears in system logs; include error code in
		// debug mode to aid troubleshooting.
		if p.debug.Load() && authResp.ErrorCode != "" {
			p.LogMessage(3 /* LOG_ERR */, fmt.Sprintf("OIDC authentication failed: %s (%s)", msg, authResp.ErrorCode))
		} else {
			p.LogMessage(3 /* LOG_ERR */, fmt.Sprintf("OIDC authentication failed: %s", msg))
		}
		return &PAMAuthFailure{
			Code:    errorCodeToPAMResult(authResp.ErrorCode),
			Message: msg,
		}
	}

	if authResp.Instructions != "" {
		p.LogMessage(6 /* LOG_INFO */, authResp.Instructions)
	}

	return nil
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
