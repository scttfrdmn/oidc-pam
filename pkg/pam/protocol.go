package pam

import (
	"encoding/json"
	"fmt"
	"os"
)

// AuthRequest represents an authentication request
type AuthRequest struct {
	Type       string            `json:"type"`
	UserID     string            `json:"user_id"`
	LoginType  string            `json:"login_type"`
	TargetHost string            `json:"target_host"`
	Metadata   map[string]string `json:"metadata"`
}

// AuthResponse represents an authentication response from the broker.
// The JSON field names mirror the IPC server Response struct.
type AuthResponse struct {
	Success          bool     `json:"success"`
	UserID           string   `json:"user_id,omitempty"`
	Email            string   `json:"email,omitempty"`
	Groups           []string `json:"groups,omitempty"`
	SessionID        string   `json:"session_id,omitempty"`
	DeviceCode       string   `json:"device_code,omitempty"` // user-visible code to enter at DeviceURL
	DeviceURL        string   `json:"device_url,omitempty"`  // URL the user must visit to complete auth
	SSHPublicKey     string   `json:"ssh_public_key,omitempty"`
	RequiresDevice   bool     `json:"requires_device,omitempty"`
	RequiresApproval bool     `json:"requires_approval,omitempty"`
	ErrorCode        string   `json:"error_code,omitempty"`
	ErrorMessage     string   `json:"error_message,omitempty"`
	Instructions     string   `json:"instructions,omitempty"`
	RiskScore        int      `json:"risk_score,omitempty"`
}

// maxUnixSocketPath is the longest broker socket path that fits
// sockaddr_un.sun_path with its NUL terminator: 108 bytes on Linux, which is the
// only platform the module runs on. The C module derives the same bound from
// sizeof(sun_path) (MAX_SOCKET_PATH in cmd/pam-module) rather than hardcoding it;
// this package has no cgo to derive it from.
const maxUnixSocketPath = 107

// IsSocketPathValid reports whether socketPath could name a Unix domain socket:
// non-empty, absolute, and short enough to fit sockaddr_un.sun_path.
func IsSocketPathValid(socketPath string) bool {
	if socketPath == "" {
		return false
	}

	if socketPath[0] != '/' {
		return false
	}

	return len(socketPath) <= maxUnixSocketPath
}

// GetLoginType determines the login type based on service and TTY
func GetLoginType(service, tty string) string {
	switch service {
	case "sshd":
		return "ssh"
	case "gdm", "lightdm", "sddm":
		return "gui"
	default:
		if tty != "" && tty != "unknown" {
			if len(tty) >= 3 && tty[:3] == "tty" {
				return "console"
			}
		}
		return "unknown"
	}
}

// BuildAuthRequest builds an authentication request
func BuildAuthRequest(username, service, rhost, tty string) *AuthRequest {
	loginType := GetLoginType(service, tty)

	metadata := map[string]string{
		"service": service,
		"tty":     tty,
		"pid":     fmt.Sprintf("%d", os.Getpid()),
	}

	return &AuthRequest{
		Type:       "authenticate",
		UserID:     username,
		LoginType:  loginType,
		TargetHost: rhost,
		Metadata:   metadata,
	}
}

// SerializeAuthRequest serializes an authentication request to JSON
func SerializeAuthRequest(req *AuthRequest) ([]byte, error) {
	return json.Marshal(req)
}
