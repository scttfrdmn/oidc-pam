package ipc

import (
	"encoding/json"
	"net"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/auth"
)

// The module's PROTOCOL_VERSION and the broker's ProtocolVersion are one number
// with two spellings, and a version mismatch is refused by both ends, so the two
// drifting apart would refuse every login on the host.
func TestProtocolVersionMatchesTheModule(t *testing.T) {
	const header = "../../cmd/pam-module/cgo_bridge.h"

	data, err := os.ReadFile(header)
	if err != nil {
		t.Fatalf("read %s: %v", header, err)
	}
	match := regexp.MustCompile(`(?m)^#define\s+PROTOCOL_VERSION\s+(\d+)`).FindSubmatch(data)
	if match == nil {
		t.Fatalf("no PROTOCOL_VERSION definition in %s; if it was renamed, update this test", header)
	}
	moduleVersion, err := strconv.Atoi(string(match[1]))
	if err != nil {
		t.Fatalf("PROTOCOL_VERSION is not a number: %v", err)
	}
	if moduleVersion != ProtocolVersion {
		t.Errorf("PROTOCOL_VERSION in %s is %d but ProtocolVersion is %d", header, moduleVersion, ProtocolVersion)
	}
}

// Broker conformance item 1: a started device flow is pending, never a success.
// pkg/auth reports one as Success together with RequiresDevice; that pair is what a
// client reading success first granted on (#146).
func TestAStartedDeviceFlowIsPendingAndNotASuccess(t *testing.T) {
	response := &Response{
		Status:         authStatus(&auth.AuthResponse{Success: true, RequiresDevice: true, SessionID: "s"}),
		Success:        true,
		RequiresDevice: true,
		UserID:         "alice",
	}
	finalizeResponse(response)

	if response.Status != StatusPending {
		t.Errorf("status = %q, want %q", response.Status, StatusPending)
	}
	if response.Success {
		t.Error("success = true for a pending device flow; version 1 says success iff authorized")
	}
	if response.UserID != "" {
		t.Errorf("user_id = %q on a pending reply; it is populated only when authorized", response.UserID)
	}
}

func TestAuthStatusMapsEveryOutcome(t *testing.T) {
	tests := []struct {
		name string
		in   auth.AuthResponse
		want string
	}{
		{"authorized", auth.AuthResponse{Success: true, UserID: "alice"}, StatusAuthorized},
		{"pending", auth.AuthResponse{Success: true, RequiresDevice: true}, StatusPending},
		{"a refusal that also sets requires_device is a refusal",
			auth.AuthResponse{RequiresDevice: true, ErrorCode: "POLICY_DENIED"}, StatusDenied},
		{"expired", auth.AuthResponse{ErrorCode: "SESSION_EXPIRED"}, StatusExpired},
		{"policy", auth.AuthResponse{ErrorCode: "POLICY_DENIED"}, StatusDenied},
		{"no local account", auth.AuthResponse{ErrorCode: "NO_LOCAL_ACCOUNT"}, StatusDenied},
		{"not found", auth.AuthResponse{ErrorCode: "SESSION_NOT_FOUND"}, StatusError},
		{"forbidden is about the caller", auth.AuthResponse{ErrorCode: "FORBIDDEN"}, StatusError},
		{"no code at all", auth.AuthResponse{}, StatusError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authStatus(&tt.in); got != tt.want {
				t.Errorf("authStatus = %q, want %q", got, tt.want)
			}
		})
	}
}

// Broker conformance item 10, both limits in one test: a capacity refusal is
// status "error", whichever limit was reached. The way this goes wrong is two
// refusals of the same shape written in different places, each self-consistent.
func TestCapacityRefusalsAreErrorsNotDenials(t *testing.T) {
	for _, code := range []string{"TOO_MANY_SESSIONS", "TOO_MANY_PENDING_AUTHS", "TOO_MANY_CONCURRENT_AUTHS"} {
		if got := authStatus(&auth.AuthResponse{ErrorCode: code}); got != StatusError {
			t.Errorf("%s: status = %q, want %q: running out of capacity is not a decision about the user",
				code, got, StatusError)
		}
	}
}

// A reply that claims success without saying it is authorized is a failure. This
// is what makes a handler that forgets to set Status fail closed rather than grant.
func TestFinalizeResponseDerivesSuccessFromStatus(t *testing.T) {
	tests := []struct {
		status      string
		wantSuccess bool
	}{
		{"", false},
		{StatusPending, false},
		{StatusDenied, false},
		{StatusExpired, false},
		{StatusError, false},
		{StatusAuthorized, true},
		{StatusRevoked, true},
	}
	for _, tt := range tests {
		response := &Response{Status: tt.status, Success: true, UserID: "alice"}
		finalizeResponse(response)

		if response.Success != tt.wantSuccess {
			t.Errorf("status %q: success = %v, want %v", tt.status, response.Success, tt.wantSuccess)
		}
		if response.ProtocolVersion != ProtocolVersion {
			t.Errorf("status %q: protocol_version = %d, want %d", tt.status, response.ProtocolVersion, ProtocolVersion)
		}
		if tt.status == "" && response.Status != StatusError {
			t.Errorf("a reply with no status went out as %q, want %q", response.Status, StatusError)
		}
		if wantUser := tt.status == StatusAuthorized; (response.UserID != "") != wantUser {
			t.Errorf("status %q: user_id = %q; it is populated only when authorized", tt.status, response.UserID)
		}
	}
}

// sendRawOverSocket writes raw bytes as the request and decodes whatever comes
// back, for requests the Request type cannot express.
func sendRawOverSocket(t *testing.T, socketPath, raw string) map[string]any {
	t.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to socket: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = conn.Write([]byte(raw + "\n"))

	var reply map[string]any
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	return reply
}

// Broker conformance items 3 and 4, over the socket: every reply carries
// protocol_version, including the ones produced before the request is dispatched,
// and a version this broker does not implement is refused and does no work.
func TestRequestProtocolVersions(t *testing.T) {
	_, socketPath := startSocketTestServer(t, newTestBroker(t), 0, 0)

	tests := []struct {
		name     string
		raw      string
		wantCode string
	}{
		// A well-formed poll for an unknown session reaches the handler, so
		// SESSION_NOT_FOUND is what "accepted" looks like here.
		{"absent means 1", `{"type":"check_session","user_id":"u","session_id":"nope"}`, "SESSION_NOT_FOUND"},
		{"null means 1", `{"protocol_version":null,"type":"check_session","user_id":"u","session_id":"nope"}`, "SESSION_NOT_FOUND"},
		{"0 means 1", `{"protocol_version":0,"type":"check_session","user_id":"u","session_id":"nope"}`, "SESSION_NOT_FOUND"},
		{"1", `{"protocol_version":1,"type":"check_session","user_id":"u","session_id":"nope"}`, "SESSION_NOT_FOUND"},
		{"a later version", `{"protocol_version":2,"type":"check_session","user_id":"u","session_id":"nope"}`, "UNSUPPORTED_PROTOCOL"},
		{"negative", `{"protocol_version":-1,"type":"check_session","user_id":"u","session_id":"nope"}`, "UNSUPPORTED_PROTOCOL"},
		{"a string fails to decode", `{"protocol_version":"1","type":"check_session","user_id":"u","session_id":"nope"}`, "INVALID_REQUEST"},
		{"non-integral fails to decode", `{"protocol_version":1.5,"type":"check_session","user_id":"u","session_id":"nope"}`, "INVALID_REQUEST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reply := sendRawOverSocket(t, socketPath, tt.raw)

			if got := reply["error_code"]; got != tt.wantCode {
				t.Errorf("error_code = %v, want %s", got, tt.wantCode)
			}
			if got, ok := reply["protocol_version"].(float64); !ok || int(got) != ProtocolVersion {
				t.Errorf("protocol_version = %v, want %d on every reply", reply["protocol_version"], ProtocolVersion)
			}
			if got := reply["status"]; got != StatusError {
				t.Errorf("status = %v, want %q", got, StatusError)
			}
			if got := reply["success"]; got != false {
				t.Errorf("success = %v, want false", got)
			}
		})
	}
}
