package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/internal/adminapi"
)

// fakeBroker is a stand-in for the broker's IPC socket: one request per
// connection, then close, as the real server behaves.
type fakeBroker struct {
	socketPath string

	mu       sync.Mutex
	requests []string
}

// requestTypes returns the request types the broker has been sent so far.
func (f *fakeBroker) requestTypes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// startFakeBroker starts a broker that answers every request with reply(type).
// A nil reply means "accept the request and say nothing".
//
// The socket lives under os.MkdirTemp rather than t.TempDir: sockaddr_un.sun_path
// is 104 bytes on macOS and the test-name-derived path from t.TempDir routinely
// exceeds it.
func startFakeBroker(t *testing.T, reply func(requestType string) any) *fakeBroker {
	t.Helper()

	dir, err := os.MkdirTemp("", "adm")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	broker := &fakeBroker{socketPath: filepath.Join(dir, "b.sock")}
	listener, err := net.Listen("unix", broker.socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	done := make(chan struct{})
	// Registered before the listener close below so that the LIFO cleanup order
	// closes the listener first and *then* waits for the accept loop to notice.
	t.Cleanup(func() { <-done })
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			var request struct {
				Type string `json:"type"`
			}
			if err := json.NewDecoder(conn).Decode(&request); err == nil {
				broker.mu.Lock()
				broker.requests = append(broker.requests, request.Type)
				broker.mu.Unlock()

				if response := reply(request.Type); response != nil {
					_ = json.NewEncoder(conn).Encode(response)
				}
			}
			_ = conn.Close()
		}
	}()

	return broker
}

func TestAdminRequestDecodesAResult(t *testing.T) {
	broker := startFakeBroker(t, func(string) any {
		return &adminapi.StatusResponse{Status: "running", Version: "v1.0.0", Uptime: "3m 0s"}
	})
	t.Setenv("OIDC_SOCKET_PATH", broker.socketPath)

	status, err := getBrokerStatus()
	if err != nil {
		t.Fatalf("getBrokerStatus: %v", err)
	}
	if status.Version != "v1.0.0" || status.Uptime != "3m 0s" {
		t.Errorf("got %+v, want version v1.0.0 and uptime 3m 0s", status)
	}
	if seen := broker.requestTypes(); len(seen) != 1 || seen[0] != "status" {
		t.Errorf("broker saw %v, want one status request", seen)
	}
}

// The failure this whole change is about: the broker refusing a request must not
// read as an answer about an idle system.
func TestAdminRequestSurfacesBrokerErrors(t *testing.T) {
	broker := startFakeBroker(t, func(string) any {
		// The shape the peer check and the validator emit.
		return map[string]any{
			"success":       false,
			"error_code":    "INVALID_REQUEST_TYPE",
			"error_message": "Invalid request type",
		}
	})
	t.Setenv("OIDC_SOCKET_PATH", broker.socketPath)

	var response adminapi.SessionListResponse
	err := adminRequest("sessions_list", &response)
	if err == nil {
		t.Fatal("a refused request was reported as success")
	}
	if !strings.Contains(err.Error(), "INVALID_REQUEST_TYPE") {
		t.Errorf("error %q does not name the broker's error code", err)
	}
}

func TestAdminRequestReportsAnUnreachableBroker(t *testing.T) {
	dir, err := os.MkdirTemp("", "adm")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// Nothing is listening here.
	t.Setenv("OIDC_SOCKET_PATH", filepath.Join(dir, "absent.sock"))

	_, err = getBrokerStatus()
	if !errors.Is(err, errBrokerUnreachable) {
		t.Fatalf("err = %v, want it to wrap errBrokerUnreachable", err)
	}
	// showSystemStatus prints STOPPED for this case rather than failing, so it
	// must not double as the "broker answered with an error" path.
	if err := showSystemStatus(); err != nil {
		t.Errorf("showSystemStatus on an unreachable broker returned %v, want nil", err)
	}
}

// A broker that accepts the connection and then says nothing must not hang the
// CLI. The deadline is requestTimeout; the test only needs to prove there is one.
func TestAdminRequestHasADeadline(t *testing.T) {
	if requestTimeout <= 0 {
		t.Fatalf("requestTimeout = %v, must be positive", requestTimeout)
	}

	broker := startFakeBroker(t, func(string) any {
		return nil // accept, read, answer nothing
	})
	t.Setenv("OIDC_SOCKET_PATH", broker.socketPath)

	deadline := time.Now().Add(requestTimeout + 5*time.Second)
	if _, err := getBrokerStatus(); err == nil {
		t.Fatal("expected an error from a broker that never answers")
	}
	if time.Now().After(deadline) {
		t.Error("the request outlived its own timeout")
	}
}

func TestSocketPathDefaultsAndOverride(t *testing.T) {
	t.Setenv("OIDC_SOCKET_PATH", "")
	if got := socketPath(); got != defaultSocketPath {
		t.Errorf("socketPath() = %q, want the default %q", got, defaultSocketPath)
	}

	t.Setenv("OIDC_SOCKET_PATH", "/run/custom.sock")
	if got := socketPath(); got != "/run/custom.sock" {
		t.Errorf("socketPath() = %q, want the override", got)
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 20, "short"},
		{"exactly-ten", 11, "exactly-ten"},
		{"a-very-long-username", 10, "a-very-..."},
		{"abcdef", 3, "abc"},
	}

	for _, tt := range tests {
		if got := truncateString(tt.in, tt.max); got != tt.want {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
		}
	}
}
