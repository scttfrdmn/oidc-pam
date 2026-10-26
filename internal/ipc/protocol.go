package ipc

import (
	"fmt"
	"strconv"

	"github.com/scttfrdmn/oidc-pam/pkg/auth"
)

// ProtocolVersion is the version of the broker<->module wire contract this broker
// speaks.
//
// The contract is oauth2-pam's (docs/wire-protocol.md in that repository): that
// project owns it and allocates its version numbers, and this one consumes it
// (#179). PROTOCOL_VERSION in cmd/pam-module/cgo_bridge.h is the module's half,
// and TestProtocolVersionMatchesTheModule holds the two equal.
const ProtocolVersion = 1

// The status values of version 1. Status is the authoritative field of a reply:
// success is derived from it, never the other way round.
const (
	StatusPending    = "pending"
	StatusAuthorized = "authorized"
	StatusDenied     = "denied"
	StatusExpired    = "expired"
	StatusError      = "error"
	StatusRevoked    = "revoked"
)

// requestProtocolVersionSupported reports whether a request's protocol_version is
// one this broker implements. Absent and 0 both mean 1: a client that predates the
// field speaks version 1 by definition. A value that is not an integer never gets
// this far — it fails to decode into Request, which is INVALID_REQUEST.
func requestProtocolVersionSupported(version int) bool {
	return version == 0 || version == ProtocolVersion
}

// deniedErrorCodes are the refusals that are decisions about the identity
// presenting itself, which is what version 1 reserves status "denied" for. Every
// other failure — capacity, rate limits, a session verb aimed at someone else's
// session, an internal error — is status "error": a capacity refusal in particular
// is a statement about the broker's load, not a judgement about the user.
//
// The first three are how a device flow ends when the identity is refused, and
// reach the wire through check_session's grace period (#179): declined at the
// provider, signed in as a different account, short of a required group. They are
// the three things the contract's "denied" row lists, and are oidc-pam's spellings
// until the contract registers its own.
var deniedErrorCodes = map[string]bool{
	"ACCESS_DENIED":             true,
	"IDENTITY_MISMATCH":         true,
	"GROUP_DENIED":              true,
	"POLICY_DENIED":             true,
	"NO_LOCAL_ACCOUNT":          true,
	"DEVICE_NOT_TRUSTED":        true,
	"GROUP_NOT_ALLOWED":         true,
	"PRIVILEGED_ACCOUNT_DENIED": true,
	"USERNAME_CLAIM_MISSING":    true,
}

// authStatus maps the broker's answer for an authenticate, check_session or
// refresh_session onto a version 1 status.
//
// A started device flow is pending whatever else the broker set on it. pkg/auth
// reports one as Success together with RequiresDevice, and that pair was the wire
// convention before status existed (#146): a client that read success first
// granted the login before anyone had visited the IdP. Here it becomes pending, and
// finalizeResponse then derives success=false from that.
func authStatus(r *auth.AuthResponse) string {
	switch {
	case r.RequiresDevice && r.ErrorCode == "":
		return StatusPending
	case r.Success:
		return StatusAuthorized
	case r.ErrorCode == "SESSION_EXPIRED":
		return StatusExpired
	case deniedErrorCodes[r.ErrorCode]:
		return StatusDenied
	default:
		return StatusError
	}
}

// finalizeResponse makes a reply conform to version 1 immediately before it is
// measured or written. Every reply to the module passes through it, including
// errors produced before the request was dispatched.
//
// It holds the rule the rest of the contract serves: success is true only when
// status is "authorized" (or "revoked", for a revocation), and user_id is
// populated only when authorized. A reply built without a status is an error
// reply. So a handler that sets Success and forgets Status sends a failure, not a
// grant: the mistake fails closed.
func finalizeResponse(r *Response) {
	r.ProtocolVersion = ProtocolVersion
	if r.Status == "" {
		r.Status = StatusError
	}
	r.Success = r.Status == StatusAuthorized || r.Status == StatusRevoked
	if r.Status != StatusAuthorized {
		r.UserID = ""
	}
}

// The login types version 1 defines. login_type is optional, and empty is treated
// as ssh; anything else is refused. It selects how the device-flow instructions are
// formatted and is recorded in the audit trail, and decides nothing.
var loginTypes = map[string]bool{"": true, "ssh": true, "console": true, "gui": true}

// requestMetadata hands a request's metadata to pkg/auth, whose AuthRequest keeps
// the generic map it has always had. The wire form is string to string; see
// Request.Metadata.
func requestMetadata(m map[string]string) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// replyMetadata renders pkg/auth's reply metadata as the string-to-string map
// version 1 defines, which is why metadata.polling_interval goes on the wire as
// "5" and not 5. Integers are written in decimal, so a client that parses the
// string gets the number the broker meant.
func replyMetadata(m map[string]interface{}) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case string:
			out[k] = val
		case int:
			out[k] = strconv.Itoa(val)
		case int64:
			out[k] = strconv.FormatInt(val, 10)
		case float64:
			out[k] = strconv.FormatFloat(val, 'f', -1, 64)
		case bool:
			out[k] = strconv.FormatBool(val)
		case nil:
			out[k] = ""
		default:
			out[k] = fmt.Sprint(val)
		}
	}
	return out
}
