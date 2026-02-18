package ipc

import (
	"fmt"
	"net"
	"regexp"
	"unicode"
)

const (
	// maxRequestSize is the maximum allowed size for a JSON request (1 MB).
	maxRequestSize = 1 << 20

	// maxUserIDLen is the maximum length for a Unix user ID.
	maxUserIDLen = 32

	// maxSessionIDLen is the maximum length for a session ID.
	maxSessionIDLen = 128

	// maxFieldLen is the maximum length for generic string fields.
	maxFieldLen = 256
)

// userIDRegexp matches valid Unix usernames: starts with a lowercase letter or
// underscore, followed by lowercase letters, digits, underscores, or hyphens,
// optionally ending with a dollar sign (for Samba machine accounts).
var userIDRegexp = regexp.MustCompile(`^[a-z_][a-z0-9_-]*[$]?$`)

// sessionIDRegexp matches alphanumeric strings with hyphens and underscores.
var sessionIDRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// validateRequest validates an IPC request based on its type.
func validateRequest(req *Request) error {
	switch req.Type {
	case "authenticate":
		if req.UserID == "" {
			return fmt.Errorf("user_id is required for authenticate requests")
		}
		if err := validateUserID(req.UserID); err != nil {
			return err
		}
		if err := validateSourceIP(req.SourceIP); err != nil {
			return err
		}
		if err := validateStringField(req.UserAgent, "user_agent", maxFieldLen); err != nil {
			return err
		}
		if err := validateStringField(req.TargetHost, "target_host", maxFieldLen); err != nil {
			return err
		}
		if err := validateStringField(req.LoginType, "login_type", maxFieldLen); err != nil {
			return err
		}
		if err := validateStringField(req.DeviceID, "device_id", maxFieldLen); err != nil {
			return err
		}
		if req.SessionID != "" {
			if err := validateSessionID(req.SessionID); err != nil {
				return err
			}
		}
		return nil

	case "check_session", "refresh_session", "revoke_session":
		if req.SessionID == "" {
			return fmt.Errorf("session_id is required for %s requests", req.Type)
		}
		return validateSessionID(req.SessionID)

	default:
		// Unknown types are handled by handleRequest; no validation needed here.
		return nil
	}
}

// validateUserID checks that a user ID is a valid Unix username.
func validateUserID(id string) error {
	if len(id) > maxUserIDLen {
		return fmt.Errorf("user_id exceeds maximum length of %d characters", maxUserIDLen)
	}
	if !userIDRegexp.MatchString(id) {
		return fmt.Errorf("user_id contains invalid characters")
	}
	return nil
}

// validateSourceIP checks that a source IP is a valid IP address.
// An empty string is allowed (source IP is optional).
func validateSourceIP(ip string) error {
	if ip == "" {
		return nil
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("source_ip is not a valid IP address")
	}
	return nil
}

// validateSessionID checks that a session ID contains only safe characters.
func validateSessionID(id string) error {
	if len(id) > maxSessionIDLen {
		return fmt.Errorf("session_id exceeds maximum length of %d characters", maxSessionIDLen)
	}
	if !sessionIDRegexp.MatchString(id) {
		return fmt.Errorf("session_id contains invalid characters")
	}
	return nil
}

// validateStringField checks that a string field does not exceed a maximum
// length and does not contain control characters.
func validateStringField(val, name string, maxLen int) error {
	if len(val) > maxLen {
		return fmt.Errorf("%s exceeds maximum length of %d characters", name, maxLen)
	}
	for _, r := range val {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains invalid control characters", name)
		}
	}
	return nil
}
