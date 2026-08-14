package ipc

import (
	"fmt"
	"net"
	"regexp"
	"unicode"
)

const (
	// maxRequestSize is the maximum allowed size for a JSON request (64 KiB).
	//
	// The largest request these limits permit is around 40 KiB: 32 metadata entries
	// of maxMetadataKeyLen + maxMetadataValueLen, plus the fixed fields. 64 KiB
	// leaves room for JSON syntax and for a field to grow, and nothing legitimate
	// comes close.
	//
	// It was 1 MiB, which mattered once rate limiting moved to after the decode
	// (#160): this bound times maxConcurrentConnections is how much a peer can make
	// the broker allocate before any limit has an opinion. 8 MiB, not 128 MiB.
	maxRequestSize = 64 << 10

	// maxUserIDLen is the maximum length for a Unix user ID.
	maxUserIDLen = 32

	// maxSessionIDLen is the maximum length for a session ID.
	maxSessionIDLen = 128

	// maxFieldLen is the maximum length for generic string fields.
	maxFieldLen = 256

	// maxMetadataKeys is the maximum number of entries in the metadata map.
	maxMetadataKeys = 32

	// maxMetadataKeyLen is the maximum length of a single metadata key.
	maxMetadataKeyLen = 64

	// maxMetadataValueLen is the maximum length of a string metadata value.
	maxMetadataValueLen = 1024
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
		if err := validateMetadata(req.Metadata); err != nil {
			return err
		}
		return nil

	case "check_session", "refresh_session", "revoke_session":
		if req.SessionID == "" {
			return fmt.Errorf("session_id is required for %s requests", req.Type)
		}
		if err := validateSessionID(req.SessionID); err != nil {
			return err
		}
		// user_id is what the broker compares against the session owner to
		// reject cross-user session access, so it is required rather than
		// optional: an absent user_id would otherwise be checked against the
		// owner as the empty string.
		if req.UserID == "" {
			return fmt.Errorf("user_id is required for %s requests", req.Type)
		}
		return validateUserID(req.UserID)

	case "status", "sessions_list", "keys_list":
		// Administrative reads. They take no parameters, so there is nothing to
		// validate: any user_id, session_id or metadata a client sends is
		// ignored by the handlers rather than rejected, since rejecting it would
		// break clients that fill in a common request struct. Authorization is
		// the socket's uid-0 peer check, not a field in the request.
		return nil

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

// validateMetadata validates the metadata map: enforces limits on key count,
// key length, and value types/sizes. Allowed value types are string, bool,
// float64 (JSON number), and nil.
func validateMetadata(m map[string]interface{}) error {
	if len(m) == 0 {
		return nil
	}
	if len(m) > maxMetadataKeys {
		return fmt.Errorf("metadata exceeds maximum of %d keys", maxMetadataKeys)
	}
	for k, v := range m {
		if len(k) == 0 {
			return fmt.Errorf("metadata key must not be empty")
		}
		if len(k) > maxMetadataKeyLen {
			return fmt.Errorf("metadata key %q exceeds maximum length of %d", k, maxMetadataKeyLen)
		}
		for _, r := range k {
			if unicode.IsControl(r) {
				return fmt.Errorf("metadata key %q contains invalid control characters", k)
			}
		}
		switch val := v.(type) {
		case nil:
			// allowed
		case bool:
			// allowed
		case float64:
			// allowed (JSON numbers decode to float64)
		case string:
			if len(val) > maxMetadataValueLen {
				return fmt.Errorf("metadata value for key %q exceeds maximum length of %d", k, maxMetadataValueLen)
			}
			for _, r := range val {
				if unicode.IsControl(r) {
					return fmt.Errorf("metadata value for key %q contains invalid control characters", k)
				}
			}
		default:
			return fmt.Errorf("metadata value for key %q has unsupported type %T (allowed: string, bool, number, null)", k, v)
		}
	}
	return nil
}
