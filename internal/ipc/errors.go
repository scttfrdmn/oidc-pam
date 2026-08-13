package ipc

// clientErrorMessage returns a generic, client-safe error message for the given
// error code. Internal details are never exposed to IPC clients — they are
// logged server-side via zerolog instead.
func clientErrorMessage(code string) string {
	switch code {
	case "INVALID_REQUEST":
		return "Invalid request"
	case "INVALID_REQUEST_TYPE":
		return "Invalid request type"
	case "AUTHENTICATION_FAILED":
		return "Authentication failed"
	case "SESSION_CHECK_FAILED":
		return "Session check failed"
	case "SESSION_REFRESH_FAILED":
		return "Session refresh failed"
	case "SESSION_REVOCATION_FAILED":
		return "Session revocation failed"
	case "POLICY_DENIED":
		return "Access denied by policy"
	case "NO_PROVIDER":
		return "No suitable authentication provider found"
	case "DEVICE_FLOW_FAILED":
		return "Device authorization flow failed"
	case "SESSION_NOT_FOUND":
		return "Session not found"
	case "SESSION_EXPIRED":
		return "Session has expired"
	case "PROVIDER_NOT_FOUND":
		return "Authentication provider not available"
	case "REFRESH_FAILED":
		return "Token refresh failed"
	case "RATE_LIMIT_EXCEEDED":
		return "Too many requests, please try again later"
	case "TOO_MANY_CONCURRENT_AUTHS":
		return "Too many concurrent authentication requests"
	case "TOO_MANY_SESSIONS":
		return "Maximum concurrent sessions reached"
	case "KEY_LIST_FAILED":
		return "Failed to list managed SSH keys"
	default:
		return "An error occurred"
	}
}
