package pam

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// What the Go client puts on the wire for the two fields that say where a login
// came from and where it is going (#169).
//
// This is the other half of TestAuthRequestCarriesSourceIPAndThisHost in
// cmd/pam-module, which asserts the same thing about the C client. The defect
// lived in both, identically, because there is no test on either side that looks
// at the request: source_ip was never sent at all, and PAM_RHOST — the address
// the user connects *from* — was sent as target_host.
func TestAuthenticateSendsSourceIPAndThisHost(t *testing.T) {
	thisHost, err := os.Hostname()
	if err != nil {
		t.Skipf("no hostname on this machine: %v", err)
	}

	tests := []struct {
		name         string
		rhost        string
		wantSourceIP string // "" means the field must be absent
		wantRHost    string // metadata.rhost; "" means absent
	}{
		{"an IPv4 peer", "10.0.0.1", "10.0.0.1", "10.0.0.1"},
		{"an IPv6 peer", "2001:db8::1", "2001:db8::1", "2001:db8::1"},
		{"a resolved hostname is audit context, not a location", "client.example.com", "", "client.example.com"},
		{"a console login has no peer at all", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socket, received := brokerRecordingRequests(t)

			module := NewPAMModule(socket, false)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := module.AuthenticateUserContext(ctx, "testuser", "sshd", tt.rhost, "pts/0"); err != nil {
				t.Fatalf("AuthenticateUserContext: %v", err)
			}

			requests := received()
			if len(requests) != 1 {
				t.Fatalf("expected exactly one request, got %d", len(requests))
			}
			req := requests[0]

			if got := stringField(req, "source_ip"); got != tt.wantSourceIP {
				t.Errorf("source_ip = %q, want %q (rhost was %q)", got, tt.wantSourceIP, tt.rhost)
			}
			if got := stringField(req, "target_host"); got != thisHost {
				t.Errorf("target_host = %q, want this host %q — target_host is the machine being "+
					"logged into, not the address the login came from", got, thisHost)
			}
			metadata, _ := req["metadata"].(map[string]interface{})
			if got := stringField(metadata, "rhost"); got != tt.wantRHost {
				t.Errorf("metadata.rhost = %q, want %q: the unabridged rhost belongs in the audit "+
					"context even when it is not an address", got, tt.wantRHost)
			}
		})
	}
}

func stringField(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}

// brokerRecordingRequests starts a broker that authorizes immediately and returns
// a snapshot of every request it was sent. One request/reply per connection, as
// the real one does.
func brokerRecordingRequests(t *testing.T) (socketPath string, received func() []map[string]interface{}) {
	t.Helper()

	// Not t.TempDir(): the path has to fit sockaddr_un.sun_path, and the temp
	// directory named after the test can be long.
	dir, err := os.MkdirTemp("", "oidcpam")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	socketPath = filepath.Join(dir, "b.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on %s: %v", socketPath, err)
	}

	var (
		mu   sync.Mutex
		seen []map[string]interface{}
		wg   sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed by cleanup
			}
			var req map[string]interface{}
			if err := json.NewDecoder(conn).Decode(&req); err == nil {
				mu.Lock()
				seen = append(seen, req)
				mu.Unlock()
				_ = json.NewEncoder(conn).Encode(map[string]interface{}{
					"success":    true,
					"status":     "authorized",
					"session_id": "sess-1",
					"user_id":    "testuser",
				})
			}
			_ = conn.Close()
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
		_ = os.RemoveAll(dir)
	})

	return socketPath, func() []map[string]interface{} {
		mu.Lock()
		defer mu.Unlock()
		out := make([]map[string]interface{}, len(seen))
		copy(out, seen)
		return out
	}
}
