package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/internal/adminapi"
	"github.com/scttfrdmn/oidc-pam/pkg/auth"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// newAdminTestServer builds a server over a real broker. The provider uses
// skip_discovery with explicit endpoints so that constructing it makes no
// network calls.
func newAdminTestServer(t *testing.T) (*Server, *auth.Broker) {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "ipc-admin")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

	cfg := &config.Config{
		Server: config.ServerConfig{SocketPath: filepath.Join(tempDir, "broker.sock")},
		OIDC: config.OIDCConfig{
			Providers: []config.OIDCProvider{
				{
					Name:            "okta",
					Issuer:          "https://okta.example.com",
					ClientID:        "test-client",
					Scopes:          []string{"openid"},
					SkipDiscovery:   true,
					TokenEndpoint:   "https://okta.example.com/token",
					DeviceEndpoint:  "https://okta.example.com/device",
					JWKSUri:         "https://okta.example.com/jwks",
					EnabledForLogin: true,
				},
			},
		},
		Authentication: config.AuthenticationConfig{
			TokenLifetime:         time.Hour,
			RefreshThreshold:      15 * time.Minute,
			MaxConcurrentSessions: 10,
		},
		Security: config.SecurityConfig{
			TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		},
	}

	broker, err := auth.NewBroker(cfg)
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}

	server, err := NewServer(filepath.Join(tempDir, "ipc.sock"), broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Stop() })

	return server, broker
}

// The three admin request types must be routed, not rejected. Before this they
// all fell through to the default case: oidc-admin has sent them since it was
// written, and the broker answered every one with INVALID_REQUEST_TYPE.
func TestAdminRequestTypesAreRouted(t *testing.T) {
	server, _ := newAdminTestServer(t)

	for requestType, want := range map[string]any{
		"status":        &adminapi.StatusResponse{},
		"sessions_list": &adminapi.SessionListResponse{},
		"keys_list":     &adminapi.KeyListResponse{},
	} {
		response := server.handleRequest(&Request{Type: requestType})

		if authResp, ok := response.(*Response); ok {
			t.Errorf("%s answered with an authentication response (error_code=%q), not %T",
				requestType, authResp.ErrorCode, want)
			continue
		}
		if got, wantType := typeName(response), typeName(want); got != wantType {
			t.Errorf("%s answered with %s, want %s", requestType, got, wantType)
		}
	}
}

func typeName(v any) string {
	return fmt.Sprintf("%T", v)
}

func TestHandleStatusReportsBrokerState(t *testing.T) {
	server, broker := newAdminTestServer(t)
	broker.SetVersion("v9.9.9")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := broker.Start(ctx); err != nil {
		t.Fatalf("broker.Start: %v", err)
	}
	defer func() { _ = broker.Stop() }()

	response, ok := server.handleRequest(&Request{Type: "status"}).(*adminapi.StatusResponse)
	if !ok {
		t.Fatal("status did not answer with a StatusResponse")
	}
	if err := response.Err(); err != nil {
		t.Fatalf("status reported an error: %v", err)
	}

	if response.Status != "running" {
		t.Errorf("status = %q, want running", response.Status)
	}
	if response.Version != "v9.9.9" {
		t.Errorf("version = %q, want v9.9.9", response.Version)
	}
	if response.StartedAt.IsZero() {
		t.Error("started_at is zero for a started broker")
	}
	// The client prints Uptime verbatim, so it must be populated even when the
	// broker has only just started.
	if response.Uptime == "" {
		t.Error("uptime is empty")
	}
	if len(response.Providers) != 1 || response.Providers[0] != "okta" {
		t.Errorf("providers = %v, want [okta]", response.Providers)
	}
	if response.Timestamp.IsZero() {
		t.Error("timestamp is zero")
	}
}

func TestHandleSessionsListOnIdleBroker(t *testing.T) {
	server, _ := newAdminTestServer(t)

	response, ok := server.handleRequest(&Request{Type: "sessions_list"}).(*adminapi.SessionListResponse)
	if !ok {
		t.Fatal("sessions_list did not answer with a SessionListResponse")
	}
	if err := response.Err(); err != nil {
		t.Fatalf("sessions_list reported an error: %v", err)
	}
	if response.Total != 0 || len(response.Sessions) != 0 {
		t.Errorf("got total=%d sessions=%v, want an empty listing", response.Total, response.Sessions)
	}

	// Encoded as [] rather than null: the client formats a table from this and
	// null is a different thing to decode into on any other client.
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"sessions":[]`)) {
		t.Errorf("empty listing encoded as %s, want \"sessions\":[]", encoded)
	}
}

func TestHandleKeysListOnBrokerWithNoKeys(t *testing.T) {
	server, _ := newAdminTestServer(t)

	response, ok := server.handleRequest(&Request{Type: "keys_list"}).(*adminapi.KeyListResponse)
	if !ok {
		t.Fatal("keys_list did not answer with a KeyListResponse")
	}
	// The broker's key directory does not exist in a test environment, which is
	// an empty listing, not an error.
	if err := response.Err(); err != nil {
		t.Fatalf("keys_list reported an error: %v", err)
	}
	if response.Total != 0 || response.Unreadable != 0 {
		t.Errorf("got total=%d unreadable=%d, want 0/0", response.Total, response.Unreadable)
	}
}

// The drift guard: what the server sends must decode into what the client reads.
// The two used to declare their own copies of these structs, and the copies
// disagreed.
func TestAdminResponsesRoundTripToClientTypes(t *testing.T) {
	server, broker := newAdminTestServer(t)
	broker.SetVersion("v1.2.3")

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(server.handleRequest(&Request{Type: "status"})); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Decoded with DisallowUnknownFields: a field the client does not know about
	// is a sign the two sides have drifted again.
	decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	decoder.DisallowUnknownFields()
	var status adminapi.StatusResponse
	if err := decoder.Decode(&status); err != nil {
		t.Fatalf("client could not decode the broker's status response: %v", err)
	}
	if status.Version != "v1.2.3" {
		t.Errorf("round-tripped version = %q, want v1.2.3", status.Version)
	}
}

// A rejected request answers with the authentication-shaped error response
// (that is what the peer check and the validator emit), so the admin response
// types must be able to see the error rather than reading it as an empty
// success.
func TestAdminClientSeesErrorShapedResponses(t *testing.T) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&Response{
		Success:      false,
		ErrorCode:    "PERMISSION_DENIED",
		ErrorMessage: "Connection rejected",
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var status adminapi.StatusResponse
	if err := json.NewDecoder(bytes.NewReader(buf.Bytes())).Decode(&status); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	err := status.Err()
	if err == nil {
		t.Fatal("a PERMISSION_DENIED response decoded as a successful status")
	}
	if !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Errorf("error %q does not mention the error code", err)
	}
}

func TestResponseSucceeded(t *testing.T) {
	tests := []struct {
		name     string
		response any
		want     bool
	}{
		{"successful auth response", &Response{Success: true}, true},
		{"denied auth response", &Response{Success: false}, false},
		{"admin result", &adminapi.StatusResponse{Status: "running"}, true},
		{"admin failure", &adminapi.KeyListResponse{
			Error: adminapi.Error{ErrorCode: "KEY_LIST_FAILED"},
		}, false},
		{"some other shape", struct{}{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := responseSucceeded(tt.response); got != tt.want {
				t.Errorf("responseSucceeded(%T) = %v, want %v", tt.response, got, tt.want)
			}
		})
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		duration time.Duration
		want     string
	}{
		{0, "0s"},
		{-time.Second, "0s"},
		{45 * time.Second, "45s"},
		{90 * time.Second, "1m 30s"},
		{2 * time.Hour, "2h 0m"},
		{25*time.Hour + 30*time.Minute, "1d 1h 30m"},
		// Rounded to the second, not printed as 2h0m0.000481723s.
		{2*time.Hour + 481723*time.Nanosecond, "2h 0m"},
	}

	for _, tt := range tests {
		if got := formatUptime(tt.duration); got != tt.want {
			t.Errorf("formatUptime(%v) = %q, want %q", tt.duration, got, tt.want)
		}
	}
}

func TestValidateRequestAcceptsAdminTypes(t *testing.T) {
	// They take no parameters, and a client that fills in a shared request struct
	// must not be rejected for it.
	for _, req := range []*Request{
		{Type: "status"},
		{Type: "sessions_list"},
		{Type: "keys_list"},
		{Type: "status", UserID: "root", SessionID: "ignored"},
	} {
		if err := validateRequest(req); err != nil {
			t.Errorf("validateRequest(%+v) = %v, want nil", req, err)
		}
	}
}
