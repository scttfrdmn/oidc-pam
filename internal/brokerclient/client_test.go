package brokerclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeBroker stands in for internal/ipc.Server. Like the real broker it serves
// exactly one newline-delimited JSON request per connection and then closes, so a
// client that fails to reconnect between polls cannot pass these tests.
type fakeBroker struct {
	socketPath string

	mu       sync.Mutex
	requests []Request
}

// newFakeBroker starts a broker whose reply to the n-th request (1-based) is
// whatever handler returns: a *Response is JSON-encoded, a string is written
// verbatim so malformed replies can be tested, and nil closes without replying.
func newFakeBroker(t *testing.T, handler func(reqNum int, req Request) interface{}) *fakeBroker {
	t.Helper()

	b := &fakeBroker{socketPath: tempSocketPath(t)}
	ln, err := net.Listen("unix", b.socketPath)
	if err != nil {
		t.Fatalf("listen on %s: %v", b.socketPath, err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed by cleanup
			}
			b.serve(conn, handler)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	return b
}

// tempSocketPath returns a short-enough path for a Unix socket. Not
// t.TempDir(): it embeds the test name, and the result routinely exceeds
// sockaddr_un.sun_path (104 bytes on macOS), which fails with EINVAL at bind.
func tempSocketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "oidcbc")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "b.sock")
}

func (b *fakeBroker) serve(conn net.Conn, handler func(int, Request) interface{}) {
	defer func() { _ = conn.Close() }()

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}

	b.mu.Lock()
	b.requests = append(b.requests, req)
	n := len(b.requests)
	b.mu.Unlock()

	switch reply := handler(n, req).(type) {
	case nil:
	case string:
		_, _ = conn.Write([]byte(reply))
	default:
		_ = json.NewEncoder(conn).Encode(reply)
	}
}

func (b *fakeBroker) received() []Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Request, len(b.requests))
	copy(out, b.requests)
	return out
}

// testClient returns a client whose clock is virtual: sleeps advance a fake
// "now" instead of taking real time, so the polling loop runs at full speed and
// the elapsed time it observes is exactly what it asked for.
func testClient(t *testing.T, socketPath string) (*Client, func() time.Time) {
	t.Helper()

	var mu sync.Mutex
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	read := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	c := New(socketPath)
	c.now = read
	c.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
		return ctx.Err()
	}
	return c, read
}

func deviceStarted(sessionID string, pollSeconds float64) *Response {
	return &Response{
		Success:        true,
		SessionID:      sessionID,
		DeviceCode:     "WDJB-MJHT",
		DeviceURL:      "https://idp.example.com/device",
		RequiresDevice: true,
		Instructions:   "Visit https://idp.example.com/device and enter WDJB-MJHT",
		Metadata: map[string]interface{}{
			"provider":         "test",
			"polling_interval": pollSeconds,
		},
	}
}

func devicePending(sessionID string) *Response {
	return &Response{
		Success:        true,
		SessionID:      sessionID,
		RequiresDevice: true,
		Metadata:       map[string]interface{}{"status": "pending"},
	}
}

func authenticated(sessionID string) *Response {
	return &Response{Success: true, SessionID: sessionID, UserID: "testuser"}
}

func denied(errorCode string) *Response {
	return &Response{Success: false, ErrorCode: errorCode, ErrorMessage: "denied by test"}
}

func authRequest() *Request {
	return &Request{UserID: "testuser", TargetHost: "10.0.0.1", LoginType: "ssh"}
}

// The headline regression test: the broker reports Success together with
// RequiresDevice as soon as the flow starts, and identity binding and
// require_groups are only enforced afterwards. Treating that as success grants
// the login before the user has proved anything.
func TestAuthenticateAndWaitDeniesWhenDeviceFlowNeverCompletes(t *testing.T) {
	broker := newFakeBroker(t, func(_ int, req Request) interface{} {
		if req.Type == "authenticate" {
			return deviceStarted("sess-never", 5)
		}
		return devicePending("sess-never")
	})

	client, _ := testClient(t, broker.socketPath)
	resp, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)
	if resp != nil {
		t.Fatalf("expected no response, got %+v", resp)
	}

	var timeout *TimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("expected *TimeoutError, got %T: %v", err, err)
	}
	if timeout.Waited != 30*time.Second {
		t.Errorf("TimeoutError.Waited = %s, want 30s", timeout.Waited)
	}

	// 30s budget at a 5s interval: one authenticate plus six polls.
	if n := len(broker.received()); n != 7 {
		t.Errorf("expected 1 authenticate + 6 polls, got %d requests", n)
	}
}

func TestAuthenticateAndWaitSucceedsAfterDeviceApproval(t *testing.T) {
	broker := newFakeBroker(t, func(n int, _ Request) interface{} {
		switch n {
		case 1:
			return deviceStarted("sess-ok", 5)
		case 2:
			return devicePending("sess-ok")
		default:
			return authenticated("sess-ok")
		}
	})

	client, _ := testClient(t, broker.socketPath)

	var shown *Response
	client.OnDeviceFlow = func(resp *Response) { shown = resp }

	resp, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)
	if err != nil {
		t.Fatalf("AuthenticateAndWait: %v", err)
	}
	if !resp.Success || resp.RequiresDevice {
		t.Fatalf("unexpected granting response: %+v", resp)
	}

	if shown == nil || shown.DeviceURL == "" {
		t.Error("OnDeviceFlow was not called with the verification details")
	}

	requests := broker.received()
	if len(requests) != 3 {
		t.Fatalf("expected 3 requests (authenticate + 2 polls), got %d", len(requests))
	}
	if requests[0].Type != "authenticate" {
		t.Errorf("first request type = %q, want authenticate", requests[0].Type)
	}
	for i, req := range requests[1:] {
		if req.Type != "check_session" {
			t.Errorf("poll %d: type = %q, want check_session", i+1, req.Type)
		}
		if req.SessionID != "sess-ok" {
			t.Errorf("poll %d: session_id = %q, want sess-ok", i+1, req.SessionID)
		}
		// The broker answers FORBIDDEN when user_id does not match the session
		// owner, so the poll has to carry it.
		if req.UserID != "testuser" {
			t.Errorf("poll %d: user_id = %q, want testuser", i+1, req.UserID)
		}
	}
}

func TestAuthenticateAndWaitDeniesOnTerminalPollErrors(t *testing.T) {
	// The broker deletes the session on identity mismatch, group denial, poll
	// failure and expiry, so these are decisions, not transient errors.
	for _, code := range []string{"SESSION_NOT_FOUND", "SESSION_EXPIRED", "FORBIDDEN", "DEVICE_FLOW_FAILED", "POLICY_DENIED"} {
		t.Run(code, func(t *testing.T) {
			broker := newFakeBroker(t, func(n int, _ Request) interface{} {
				if n == 1 {
					return deviceStarted("sess-gone", 5)
				}
				return denied(code)
			})

			client, _ := testClient(t, broker.socketPath)
			_, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)

			var denial *DenialError
			if !errors.As(err, &denial) {
				t.Fatalf("expected *DenialError, got %T: %v", err, err)
			}
			if denial.ErrorCode != code {
				t.Errorf("DenialError.ErrorCode = %q, want %q", denial.ErrorCode, code)
			}
			if n := len(broker.received()); n != 2 {
				t.Errorf("expected polling to stop at the first terminal answer, got %d requests", n)
			}
		})
	}
}

func TestAuthenticateAndWaitGrantsActiveSessionWithoutPolling(t *testing.T) {
	broker := newFakeBroker(t, func(_ int, _ Request) interface{} {
		return authenticated("sess-active")
	})

	client, _ := testClient(t, broker.socketPath)
	resp, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)
	if err != nil {
		t.Fatalf("AuthenticateAndWait: %v", err)
	}
	if resp.SessionID != "sess-active" {
		t.Errorf("session_id = %q, want sess-active", resp.SessionID)
	}
	if n := len(broker.received()); n != 1 {
		t.Errorf("expected exactly 1 request, got %d", n)
	}
}

func TestAuthenticateAndWaitDeniesUpFront(t *testing.T) {
	for _, code := range []string{"NO_PROVIDER", "POLICY_DENIED", "RATE_LIMITED", "AUTHENTICATION_FAILED", ""} {
		name := code
		if name == "" {
			name = "no_error_code"
		}
		t.Run(name, func(t *testing.T) {
			broker := newFakeBroker(t, func(_ int, _ Request) interface{} {
				return denied(code)
			})

			client, _ := testClient(t, broker.socketPath)
			_, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)

			var denial *DenialError
			if !errors.As(err, &denial) {
				t.Fatalf("expected *DenialError, got %T: %v", err, err)
			}
			if n := len(broker.received()); n != 1 {
				t.Errorf("a refusal must not be polled: got %d requests", n)
			}
		})
	}
}

// A refusal that also sets requires_device is still a refusal.
func TestAuthenticateAndWaitDeniesRefusalWithRequiresDevice(t *testing.T) {
	broker := newFakeBroker(t, func(_ int, _ Request) interface{} {
		return &Response{Success: false, RequiresDevice: true, ErrorCode: "RATE_LIMITED"}
	})

	client, _ := testClient(t, broker.socketPath)
	_, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)

	var denial *DenialError
	if !errors.As(err, &denial) {
		t.Fatalf("expected *DenialError, got %T: %v", err, err)
	}
}

// Failing to reach an opinion must be distinguishable from a denial: callers
// return PAM_AUTHINFO_UNAVAIL for these and PAM_AUTH_ERR for denials.
func TestAuthenticateAndWaitTransportFailuresAreNotDenials(t *testing.T) {
	assertPlainError := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected an error")
		}
		var denial *DenialError
		var timeout *TimeoutError
		if errors.As(err, &denial) || errors.As(err, &timeout) {
			t.Fatalf("transport failure reported as a decision: %T: %v", err, err)
		}
	}

	t.Run("no broker listening", func(t *testing.T) {
		client := New(tempSocketPath(t))
		_, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)
		assertPlainError(t, err)
	})

	t.Run("malformed JSON", func(t *testing.T) {
		broker := newFakeBroker(t, func(_ int, _ Request) interface{} { return `{"success":` })
		client, _ := testClient(t, broker.socketPath)
		_, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)
		assertPlainError(t, err)
	})

	t.Run("closed without a reply", func(t *testing.T) {
		broker := newFakeBroker(t, func(_ int, _ Request) interface{} { return nil })
		client, _ := testClient(t, broker.socketPath)
		_, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)
		assertPlainError(t, err)
	})

	t.Run("device flow without a session_id", func(t *testing.T) {
		broker := newFakeBroker(t, func(_ int, _ Request) interface{} {
			return &Response{Success: true, RequiresDevice: true}
		})
		client, _ := testClient(t, broker.socketPath)
		_, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)
		assertPlainError(t, err)
	})

	t.Run("poll cannot reach the broker", func(t *testing.T) {
		// Reply to the authenticate, then stop listening entirely.
		socketPath := tempSocketPath(t)
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req Request
			_ = json.NewDecoder(conn).Decode(&req)
			_ = json.NewEncoder(conn).Encode(deviceStarted("sess-1", 5))
			_ = conn.Close()
			_ = ln.Close()
			_ = os.Remove(socketPath)
		}()

		client, _ := testClient(t, socketPath)
		_, err = client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)
		assertPlainError(t, err)
	})
}

func TestAuthenticateAndWaitHonorsContextCancellation(t *testing.T) {
	broker := newFakeBroker(t, func(n int, _ Request) interface{} {
		if n == 1 {
			return deviceStarted("sess-1", 5)
		}
		return devicePending("sess-1")
	})

	ctx, cancel := context.WithCancel(context.Background())
	client, _ := testClient(t, broker.socketPath)
	// The virtual clock returns ctx.Err() from sleep, so cancelling before the
	// first wait ends the loop immediately.
	cancel()

	_, err := client.AuthenticateAndWait(ctx, authRequest(), 30*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %T: %v", err, err)
	}
}

func TestPollIntervalClamping(t *testing.T) {
	tests := []struct {
		name string
		meta map[string]interface{}
		want time.Duration
	}{
		{"absent metadata", nil, DefaultPollInterval},
		{"absent key", map[string]interface{}{"provider": "test"}, DefaultPollInterval},
		{"non-numeric", map[string]interface{}{"polling_interval": "5"}, DefaultPollInterval},
		{"in range", map[string]interface{}{"polling_interval": float64(7)}, 7 * time.Second},
		{"zero clamps up", map[string]interface{}{"polling_interval": float64(0)}, MinPollInterval},
		{"negative clamps up", map[string]interface{}{"polling_interval": float64(-10)}, MinPollInterval},
		{"huge clamps down", map[string]interface{}{"polling_interval": float64(3600)}, MaxPollInterval},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pollInterval(&Response{Metadata: tt.meta}); got != tt.want {
				t.Errorf("pollInterval = %s, want %s", got, tt.want)
			}
		})
	}
}

// The wait must not overshoot the budget: the last sleep is shortened to what
// remains rather than sleeping a whole interval past the deadline.
func TestAuthenticateAndWaitDoesNotOvershootTheBudget(t *testing.T) {
	broker := newFakeBroker(t, func(n int, _ Request) interface{} {
		if n == 1 {
			return deviceStarted("sess-1", 20)
		}
		return devicePending("sess-1")
	})

	client, now := testClient(t, broker.socketPath)
	start := now()

	_, err := client.AuthenticateAndWait(context.Background(), authRequest(), 30*time.Second)
	var timeout *TimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("expected *TimeoutError, got %T: %v", err, err)
	}

	if elapsed := now().Sub(start); elapsed != 30*time.Second {
		t.Errorf("waited %s, want exactly the 30s budget", elapsed)
	}
}

// (#169) source_ip is where the login came from, and it carries an address or
// nothing. A hostname — what PAM_RHOST holds when sshd runs with UseDNS on — is
// dropped rather than passed through, because the broker's network policies, IP
// allowlists and location history all treat what is in this field as a location
// and nothing re-resolves it.
func TestSourceIPFromRHost(t *testing.T) {
	tests := []struct {
		name  string
		rhost string
		want  string
	}{
		{"IPv4", "10.0.0.1", "10.0.0.1"},
		{"IPv6", "2001:db8::1", "2001:db8::1"},
		{"IPv6 with zone", "fe80::1%eth0", "fe80::1%eth0"},
		{"loopback", "127.0.0.1", "127.0.0.1"},
		{"a resolved hostname is not an address", "client.example.com", ""},
		{"the module's old stand-in for a local login", "localhost", ""},
		{"a local login has no peer", "", ""},
		{"longer than the contract allows", "1234567890123456789012345678901234567890123456", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SourceIPFromRHost(tt.rhost); got != tt.want {
				t.Errorf("SourceIPFromRHost(%q) = %q, want %q", tt.rhost, got, tt.want)
			}
		})
	}
}

// target_host is the host being logged into, which is this one — not the client's
// address, which is what both clients used to send.
func TestThisHostIsThisHost(t *testing.T) {
	want, err := os.Hostname()
	if err != nil {
		t.Skipf("no hostname on this machine: %v", err)
	}
	if got := ThisHost(); got != want {
		t.Errorf("ThisHost() = %q, want this machine's name %q", got, want)
	}
}
