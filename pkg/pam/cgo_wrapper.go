package pam

/*
#cgo CFLAGS: -I/usr/include/security -I/opt/homebrew/include
#cgo LDFLAGS: -lpam -ljson-c -L/opt/homebrew/lib
#include "cgo_bridge.h"
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// AuthRequest represents an authentication request
type AuthRequest struct {
	Type       string            `json:"type"`
	UserID     string            `json:"user_id"`
	LoginType  string            `json:"login_type"`
	TargetHost string            `json:"target_host"`
	Metadata   map[string]string `json:"metadata"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	Success        bool   `json:"success"`
	RequiresDevice bool   `json:"requires_device,omitempty"`
	Instructions   string `json:"instructions,omitempty"`
	ErrorMessage   string `json:"error,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
}

// ConnectToBroker connects to the authentication broker
func ConnectToBroker(socketPath string) (int, error) {
	cSocketPath := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cSocketPath))
	
	sock := C.connect_to_broker(cSocketPath)
	if sock == -1 {
		return -1, fmt.Errorf("failed to connect to broker at %s", socketPath)
	}
	
	return int(sock), nil
}

// SendAuthRequest sends an authentication request to the broker
func SendAuthRequest(sock int, username, service, rhost, tty string) error {
	cUsername := C.CString(username)
	cService := C.CString(service)
	cRhost := C.CString(rhost)
	cTTY := C.CString(tty)
	
	defer C.free(unsafe.Pointer(cUsername))
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cRhost))
	defer C.free(unsafe.Pointer(cTTY))
	
	result := C.send_auth_request(C.int(sock), cUsername, cService, cRhost, cTTY)
	if result != 0 {
		return fmt.Errorf("failed to send authentication request")
	}
	
	return nil
}

// ReceiveAuthResponse receives an authentication response from the broker
func ReceiveAuthResponse(sock int) (*AuthResponse, error) {
	var response [4096]C.char
	
	result := C.receive_auth_response(C.int(sock), &response[0], 4096)
	if result != 0 {
		return nil, fmt.Errorf("failed to receive authentication response")
	}
	
	responseStr := C.GoString(&response[0])
	if responseStr == "" {
		return nil, fmt.Errorf("empty response from broker")
	}
	
	var authResponse AuthResponse
	if err := json.Unmarshal([]byte(responseStr), &authResponse); err != nil {
		return nil, fmt.Errorf("failed to parse authentication response: %w", err)
	}
	
	return &authResponse, nil
}

// LogPAMMessage logs a message through the PAM logging system
func LogPAMMessage(priority int, message string) {
	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))
	
	C.log_pam_message_string(C.int(priority), cMessage)
}

// CloseSocket closes the socket connection
func CloseSocket(sock int) {
	C.close(C.int(sock))
}

// IsSocketPathValid checks if the socket path is valid
func IsSocketPathValid(socketPath string) bool {
	if socketPath == "" {
		return false
	}
	
	// Check if path starts with /
	if socketPath[0] != '/' {
		return false
	}
	
	// Check maximum path length
	if len(socketPath) > 107 { // Maximum Unix domain socket path length
		return false
	}
	
	return true
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
			if tty[:3] == "tty" {
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
		"pid":     fmt.Sprintf("%d", C.getpid()),
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