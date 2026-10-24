package ipc

import "github.com/scttfrdmn/oidc-pam/pkg/auth"

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
var deniedErrorCodes = map[string]bool{
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
