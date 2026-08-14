package pam

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/scttfrdmn/oidc-pam/internal/brokerclient"
)

// AuthRequest represents an authentication request.
//
// SourceIP is where the login came from and TargetHost is where it is going: this
// host. See BuildAuthRequest (#169).
type AuthRequest struct {
	Type       string            `json:"type"`
	UserID     string            `json:"user_id"`
	LoginType  string            `json:"login_type"`
	SourceIP   string            `json:"source_ip,omitempty"`
	TargetHost string            `json:"target_host,omitempty"`
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

// BuildAuthRequest builds an authentication request.
//
// (#169) rhost is PAM_RHOST — where the login is coming from — so it becomes
// source_ip, and only when it really is an address; target_host is this machine.
// This used to put rhost in target_host and send no source_ip, which is the
// inversion the broker's policies were then evaluated against.
func BuildAuthRequest(username, service, rhost, tty string) *AuthRequest {
	loginType := GetLoginType(service, tty)

	metadata := map[string]string{
		"service": service,
		"tty":     tty,
		"pid":     fmt.Sprintf("%d", os.Getpid()),
	}
	if rhost != "" {
		metadata["rhost"] = rhost
	}

	return &AuthRequest{
		Type:       "authenticate",
		UserID:     username,
		LoginType:  loginType,
		SourceIP:   brokerclient.SourceIPFromRHost(rhost),
		TargetHost: brokerclient.ThisHost(),
		Metadata:   metadata,
	}
}

// SerializeAuthRequest serializes an authentication request to JSON
func SerializeAuthRequest(req *AuthRequest) ([]byte, error) {
	return json.Marshal(req)
}
