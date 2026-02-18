package ipc

import "testing"

func TestClientErrorMessageKnownCodes(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"INVALID_REQUEST", "Invalid request"},
		{"INVALID_REQUEST_TYPE", "Invalid request type"},
		{"AUTHENTICATION_FAILED", "Authentication failed"},
		{"SESSION_CHECK_FAILED", "Session check failed"},
		{"SESSION_REFRESH_FAILED", "Session refresh failed"},
		{"SESSION_REVOCATION_FAILED", "Session revocation failed"},
		{"POLICY_DENIED", "Access denied by policy"},
		{"NO_PROVIDER", "No suitable authentication provider found"},
		{"DEVICE_FLOW_FAILED", "Device authorization flow failed"},
		{"SESSION_NOT_FOUND", "Session not found"},
		{"SESSION_EXPIRED", "Session has expired"},
		{"PROVIDER_NOT_FOUND", "Authentication provider not available"},
		{"REFRESH_FAILED", "Token refresh failed"},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := clientErrorMessage(tt.code)
			if got != tt.expected {
				t.Errorf("clientErrorMessage(%q) = %q, want %q", tt.code, got, tt.expected)
			}
		})
	}
}

func TestClientErrorMessageUnknownCode(t *testing.T) {
	unknownCodes := []string{"", "UNKNOWN", "something_random", "invalid_request"}
	for _, code := range unknownCodes {
		t.Run(code, func(t *testing.T) {
			got := clientErrorMessage(code)
			if got != "An error occurred" {
				t.Errorf("clientErrorMessage(%q) = %q, want %q", code, got, "An error occurred")
			}
		})
	}
}
