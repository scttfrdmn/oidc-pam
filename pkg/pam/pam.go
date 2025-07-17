package pam

/*
#cgo CFLAGS: -I/usr/include/security -I/opt/homebrew/include
#cgo LDFLAGS: -lpam -ljson-c -L/opt/homebrew/lib
#include "cgo_bridge.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// PAMModule represents the PAM module interface
type PAMModule struct {
	socketPath string
	debug      bool
}

// NewPAMModule creates a new PAM module instance
func NewPAMModule(socketPath string, debug bool) *PAMModule {
	return &PAMModule{
		socketPath: socketPath,
		debug:      debug,
	}
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
	
	// Receive response
	var response [4096]C.char
	if C.receive_auth_response(sock, &response[0], 4096) != 0 {
		return fmt.Errorf("failed to receive authentication response")
	}
	
	// For now, we'll implement a simple success/failure check
	// In a real implementation, we'd parse the JSON response
	responseStr := C.GoString(&response[0])
	if responseStr == "" {
		return fmt.Errorf("empty response from broker")
	}
	
	// Simple check for success - in practice, we'd parse JSON
	if responseStr == "{\"success\":true}" {
		return nil
	}
	
	return fmt.Errorf("authentication failed")
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
	return p.debug
}

// SetDebug enables or disables debug mode
func (p *PAMModule) SetDebug(enabled bool) {
	p.debug = enabled
}