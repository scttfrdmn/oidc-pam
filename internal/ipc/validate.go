package ipc

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
)

const (
	// maxRequestSize is the maximum allowed size for a JSON request (64 KiB).
	//
	// It is the contract's cap on a request read (version 1, broker conformance
	// item 6), and the reference client's requests are a few hundred bytes, so
	// nothing legitimate comes close.
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

	// maxSourceIPLen and maxTargetHostLen are the wire contract's bounds for these
	// two fields: 45 bytes is an IPv6 literal with a zone, 253 a DNS name. They are
	// what Broker.Authenticate already enforces, applied at the boundary instead so
	// an over-long value is refused before it is copied anywhere.
	maxSourceIPLen   = 45
	maxTargetHostLen = 253

	// maxUserAgentLen is version 1's bound on user_agent.
	maxUserAgentLen = 512

	// The bounds version 1 sets on the metadata map: how many entries, and how long
	// each key and each value may be. Together they permit more than maxRequestSize,
	// which is the bound that binds first; they exist so that no single entry is a
	// way to put an unbounded string in an audit record.
	maxMetadataKeys     = 64
	maxMetadataKeyLen   = 128
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
		if err := validateStringField(req.UserAgent, "user_agent", maxUserAgentLen); err != nil {
			return err
		}
		if err := validateStringField(req.TargetHost, "target_host", maxTargetHostLen); err != nil {
			return err
		}
		if !loginTypes[req.LoginType] {
			return fmt.Errorf("login_type must be ssh, console or gui")
		}
		if err := validateStringField(req.DeviceID, "device_id", maxFieldLen); err != nil {
			return err
		}
		if err := validateStringField(req.Provider, "provider", maxFieldLen); err != nil {
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

// validateSourceIP checks that source_ip is an IP address, or absent.
//
// Empty stays legal, because the wire contract makes source_ip conditional on the
// login having an address at all ("the client address, if the login has one"), and
// a console login has none. What used to be wrong was not the validation but what
// the policy engine made of the gap: see applyNetworkPolicies (#169). A hostname
// is refused rather than accepted as a location — an unresolvable claim in
// source_ip is worse than nothing, since a policy would evaluate it — and clients
// put the unabridged PAM_RHOST in metadata.rhost instead.
func validateSourceIP(ip string) error {
	if ip == "" {
		return nil
	}
	if len(ip) > maxSourceIPLen {
		return fmt.Errorf("source_ip exceeds maximum length of %d characters", maxSourceIPLen)
	}
	// An IPv6 literal may carry a zone ("fe80::1%eth0"), which net.ParseIP rejects
	// on its own. The zone names an interface on the sending host and means nothing
	// here, so it is accepted and ignored.
	addr := ip
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	if net.ParseIP(addr) == nil {
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

// validateMetadata validates the metadata map against version 1's bounds: at most
// maxMetadataKeys entries, each key non-empty and at most maxMetadataKeyLen bytes,
// each value at most maxMetadataValueLen, and no control characters in either.
// That every value is a string is enforced by the type the request decodes into.
func validateMetadata(m map[string]string) error {
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
		if len(v) > maxMetadataValueLen {
			return fmt.Errorf("metadata value for key %q exceeds maximum length of %d", k, maxMetadataValueLen)
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				return fmt.Errorf("metadata value for key %q contains invalid control characters", k)
			}
		}
	}
	return nil
}
