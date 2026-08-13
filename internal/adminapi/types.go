// Package adminapi holds the wire types for the broker's administrative IPC
// requests — `status`, `sessions_list` and `keys_list`, as issued by oidc-admin.
//
// They live here, in a package with no dependencies beyond the standard library,
// so that the broker (internal/ipc) and the client (cmd/oidc-admin) encode and
// decode the same structs. They were previously declared twice, once on each
// side, and the two copies had drifted to the point where the client sent
// request types the broker did not implement at all: every `oidc-admin status`
// got back an authentication error response, which decoded into an empty
// StatusResponse and printed as a running broker with no version and no uptime.
package adminapi

import (
	"fmt"
	"time"
)

// Error is embedded in every admin response so that a failure can be reported
// in the shape the client is already decoding, rather than as a different
// object the client would silently read as an empty success.
type Error struct {
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// Err reports the failure the response carries, or nil if it carries a result.
// A client that decodes a response must check it: the zero value of every
// response type below is indistinguishable from a real answer about an idle
// broker, so an unchecked error prints as "no sessions" or "no keys".
func (e Error) Err() error {
	if e.ErrorCode == "" {
		return nil
	}
	if e.ErrorMessage == "" {
		return fmt.Errorf("broker returned error %s", e.ErrorCode)
	}
	return fmt.Errorf("broker returned error %s: %s", e.ErrorCode, e.ErrorMessage)
}

// StatusResponse answers a `status` request.
type StatusResponse struct {
	Error
	// Status is a one-word summary: "running" or "degraded".
	Status string `json:"status"`
	// Version is the broker binary's version, as set at build time.
	Version string `json:"version"`
	// Uptime is how long the broker has been serving, formatted for display.
	Uptime string `json:"uptime"`
	// UptimeSeconds is the same value for programmatic consumers.
	UptimeSeconds float64 `json:"uptime_seconds"`
	// StartedAt is when the broker's services started.
	StartedAt time.Time `json:"started_at"`
	// ActiveSessions counts sessions that have completed authentication;
	// PendingSessions counts device flows still waiting on the user.
	ActiveSessions  int `json:"active_sessions"`
	PendingSessions int `json:"pending_sessions"`
	// Providers lists the configured OIDC providers, enabled or not.
	Providers []string `json:"providers"`
	// Timestamp is when the broker answered.
	Timestamp time.Time `json:"timestamp"`
}

// Session describes one authentication session.
//
// Deliberately omitted: the session's tokens (the broker no longer holds them in
// plaintext), its token ID, and the user's group memberships. A listing exists to
// answer "who is logged in", and root can read the audit log for the rest.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Provider  string    `json:"provider"`
	LoginType string    `json:"login_type"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Status is "active" for an authenticated session, "pending" for a device
	// flow the user has not completed, and "expired" for one past ExpiresAt that
	// the cleanup sweep has not reached yet.
	Status string `json:"status"`
}

// SessionListResponse answers a `sessions_list` request.
type SessionListResponse struct {
	Error
	Sessions []Session `json:"sessions"`
	Total    int       `json:"total"`
}

// SSHKeyInfo describes one broker-managed SSH key pair. Only public metadata
// appears here — never the key material itself.
type SSHKeyInfo struct {
	Username string `json:"username"`
	// KeyType is the SSH algorithm name, e.g. "ssh-rsa".
	KeyType string `json:"key_type"`
	// KeySize is the key's strength in bits.
	KeySize   int       `json:"key_size"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// KeyListResponse answers a `keys_list` request.
type KeyListResponse struct {
	Error
	Keys  []SSHKeyInfo `json:"keys"`
	Total int          `json:"total"`
	// Unreadable counts key directories that could not be read. They are omitted
	// from Keys, so without this the listing would look complete when it is not.
	Unreadable int `json:"unreadable,omitempty"`
}
