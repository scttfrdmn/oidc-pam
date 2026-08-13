package pam

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fakeBroker is a minimal stand-in for internal/ipc.Server. Like the real
// broker it serves exactly one newline-delimited JSON request per connection and
// then closes, so a module that fails to reconnect between polls cannot pass
// these tests.
type fakeBroker struct {
	socketPath string

	mu       sync.Mutex
	requests []map[string]interface{}
}

// newFakeBroker starts a broker whose reply to the n-th request (1-based) is
// whatever handler returns: a map/struct is JSON-encoded, a string is written
// verbatim so malformed responses can be tested.
func newFakeBroker(t *testing.T, handler func(reqNum int, req map[string]interface{}) interface{}) *fakeBroker {
	t.Helper()

	// Not t.TempDir(): the socket path has to fit in sockaddr_un.sun_path, and
	// the temp directory named after the test can be long.
	dir, err := os.MkdirTemp("", "oidcpam")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}

	b := &fakeBroker{socketPath: filepath.Join(dir, "b.sock")}
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
		_ = os.RemoveAll(dir)
	})

	return b
}

func (b *fakeBroker) serve(conn net.Conn, handler func(int, map[string]interface{}) interface{}) {
	defer func() { _ = conn.Close() }()

	var req map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}

	b.mu.Lock()
	b.requests = append(b.requests, req)
	n := len(b.requests)
	b.mu.Unlock()

	switch reply := handler(n, req).(type) {
	case nil:
		// Close without replying.
	case string:
		_, _ = conn.Write([]byte(reply))
	default:
		_ = json.NewEncoder(conn).Encode(reply)
	}
}

func (b *fakeBroker) received() []map[string]interface{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]map[string]interface{}, len(b.requests))
	copy(out, b.requests)
	return out
}

// deviceStarted is what the broker returns when it has only just started the
// device flow: success=true *and* requires_device=true. The user has not
// authenticated yet at this point.
func deviceStarted(sessionID string) map[string]interface{} {
	return map[string]interface{}{
		"success":         true,
		"session_id":      sessionID,
		"device_code":     "WDJB-MJHT",
		"device_url":      "https://idp.example.com/device",
		"requires_device": true,
		"instructions":    "Visit https://idp.example.com/device and enter WDJB-MJHT",
		"metadata": map[string]interface{}{
			"provider":         "test",
			"polling_interval": 1,
		},
	}
}

// devicePending is CheckSession's reply while the user has not finished: also
// success=true with requires_device=true.
func devicePending(sessionID string) map[string]interface{} {
	return map[string]interface{}{
		"success":         true,
		"session_id":      sessionID,
		"requires_device": true,
		"metadata":        map[string]interface{}{"status": "pending"},
	}
}

func authenticated(sessionID string) map[string]interface{} {
	return map[string]interface{}{
		"success":    true,
		"session_id": sessionID,
		"user_id":    "testuser",
		"email":      "testuser@example.com",
	}
}

func denied(errorCode string) map[string]interface{} {
	return map[string]interface{}{
		"success":       false,
		"error_code":    errorCode,
		"error_message": "denied by test",
	}
}

// The headline regression test: the broker reports success=true together with
// requires_device=true as soon as the device flow starts, and the identity
// binding and require_groups checks only happen afterwards. If the module reads
// success before requires_device it returns PAM_SUCCESS here, and with the
// shipped `auth sufficient pam_oidc.so` that grants login to anyone who can
// reach the broker without them ever visiting the device URL.
func TestPerformAuthenticationDeniesWhenDeviceFlowNeverCompletes(t *testing.T) {
	t.Parallel()

	broker := newFakeBroker(t, func(_ int, req map[string]interface{}) interface{} {
		if req["type"] == "authenticate" {
			return deviceStarted("sess-never")
		}
		return devicePending("sess-never")
	})

	if got := performAuthentication(broker.socketPath, "testuser", "sshd", "10.0.0.1", "ssh", 2); got != PAMAuthError {
		t.Fatalf("unfinished device flow: got PAM result %d, want PAMAuthError (%d)", got, PAMAuthError)
	}

	// One authenticate plus at least one poll: the module must actually wait for
	// the user rather than deciding on the initiation response alone.
	if n := len(broker.received()); n < 2 {
		t.Fatalf("expected the module to poll the broker, got %d request(s)", n)
	}
}

func TestPerformAuthenticationSucceedsAfterDeviceApproval(t *testing.T) {
	t.Parallel()

	broker := newFakeBroker(t, func(n int, _ map[string]interface{}) interface{} {
		switch n {
		case 1:
			return deviceStarted("sess-ok")
		case 2:
			return devicePending("sess-ok")
		default:
			return authenticated("sess-ok")
		}
	})

	if got := performAuthentication(broker.socketPath, "testuser", "sshd", "10.0.0.1", "ssh", 30); got != PAMSuccess {
		t.Fatalf("completed device flow: got PAM result %d, want PAMSuccess", got)
	}

	requests := broker.received()
	if len(requests) != 3 {
		t.Fatalf("expected 3 requests (authenticate + 2 polls), got %d: %v", len(requests), requests)
	}
	if requests[0]["type"] != "authenticate" {
		t.Errorf("first request type = %v, want authenticate", requests[0]["type"])
	}
	for i, req := range requests[1:] {
		if req["type"] != "check_session" {
			t.Errorf("poll %d: type = %v, want check_session", i+1, req["type"])
		}
		if req["session_id"] != "sess-ok" {
			t.Errorf("poll %d: session_id = %v, want sess-ok", i+1, req["session_id"])
		}
		// Broker.CheckSession answers FORBIDDEN when user_id does not match the
		// session owner, so the poll has to carry it.
		if req["user_id"] != "testuser" {
			t.Errorf("poll %d: user_id = %v, want testuser", i+1, req["user_id"])
		}
	}
}

// The broker deletes the session when identity binding fails, when
// require_groups rejects the user, when polling the IdP fails, and when the
// session expires. A poll that can no longer find its session is therefore a
// denial, not a transient error.
func TestPerformAuthenticationDeniesOnTerminalPollErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		errorCode string
		want      PAMResultCode
	}{
		{"SESSION_NOT_FOUND", PAMAuthError},
		{"SESSION_EXPIRED", PAMAuthError},
		{"FORBIDDEN", PAMAuthError},
		{"DEVICE_FLOW_FAILED", PAMAuthError},
		{"POLICY_DENIED", PAMPermDenied},
		{"TOO_MANY_SESSIONS", PAMPermDenied},
		{"RATE_LIMITED", PAMMaxTries},
	}

	for _, tt := range tests {
		t.Run(tt.errorCode, func(t *testing.T) {
			t.Parallel()

			broker := newFakeBroker(t, func(n int, _ map[string]interface{}) interface{} {
				if n == 1 {
					return deviceStarted("sess-gone")
				}
				return denied(tt.errorCode)
			})

			if got := performAuthentication(broker.socketPath, "testuser", "sshd", "10.0.0.1", "ssh", 30); got != tt.want {
				t.Fatalf("poll answered %s: got PAM result %d, want %d", tt.errorCode, got, tt.want)
			}
		})
	}
}

// A session already active on the broker (no device step) is granted from the
// first response, without polling.
func TestPerformAuthenticationSucceedsWithoutDeviceStep(t *testing.T) {
	t.Parallel()

	broker := newFakeBroker(t, func(_ int, _ map[string]interface{}) interface{} {
		return authenticated("sess-active")
	})

	if got := performAuthentication(broker.socketPath, "testuser", "sshd", "10.0.0.1", "ssh", 30); got != PAMSuccess {
		t.Fatalf("active session: got PAM result %d, want PAMSuccess", got)
	}
	if n := len(broker.received()); n != 1 {
		t.Fatalf("expected exactly 1 request, got %d", n)
	}
}

func TestPerformAuthenticationDeniesUpFront(t *testing.T) {
	t.Parallel()

	tests := []struct {
		errorCode string
		want      PAMResultCode
	}{
		{"NO_PROVIDER", PAMPermDenied},
		{"POLICY_DENIED", PAMPermDenied},
		{"TOO_MANY_CONCURRENT_AUTHS", PAMMaxTries},
		{"RATE_LIMIT_EXCEEDED", PAMMaxTries},
		{"AUTHENTICATION_FAILED", PAMAuthError},
		{"", PAMAuthError},
	}

	for _, tt := range tests {
		name := tt.errorCode
		if name == "" {
			name = "no_error_code"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			broker := newFakeBroker(t, func(_ int, _ map[string]interface{}) interface{} {
				return denied(tt.errorCode)
			})

			if got := performAuthentication(broker.socketPath, "testuser", "sshd", "10.0.0.1", "ssh", 30); got != tt.want {
				t.Fatalf("broker returned %s: got PAM result %d, want %d", tt.errorCode, got, tt.want)
			}
			if n := len(broker.received()); n != 1 {
				t.Fatalf("a refusal must not be polled: got %d requests", n)
			}
		})
	}
}

// Only being unable to reach an opinion — no broker, an unreadable response —
// may return PAM_AUTHINFO_UNAVAIL. Everything else has to fail closed.
func TestPerformAuthenticationUnavailable(t *testing.T) {
	t.Parallel()

	t.Run("no broker listening", func(t *testing.T) {
		t.Parallel()

		dir, err := os.MkdirTemp("", "oidcpam")
		if err != nil {
			t.Fatalf("MkdirTemp: %v", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()

		got := performAuthentication(filepath.Join(dir, "absent.sock"), "testuser", "sshd", "10.0.0.1", "ssh", 30)
		if got != PAMAuthInfoUnavail {
			t.Fatalf("absent broker: got PAM result %d, want PAMAuthInfoUnavail (%d)", got, PAMAuthInfoUnavail)
		}
	})

	unreadable := []struct {
		name  string
		reply interface{}
	}{
		{"malformed JSON", `{"success":`},
		{"no success field", map[string]interface{}{"session_id": "sess-1"}},
		{"connection closed without a reply", nil},
		{
			name: "device flow without a session_id",
			reply: map[string]interface{}{
				"success":         true,
				"requires_device": true,
			},
		},
	}

	for _, tt := range unreadable {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			broker := newFakeBroker(t, func(_ int, _ map[string]interface{}) interface{} {
				return tt.reply
			})

			got := performAuthentication(broker.socketPath, "testuser", "sshd", "10.0.0.1", "ssh", 30)
			if got != PAMAuthInfoUnavail {
				t.Fatalf("got PAM result %d, want PAMAuthInfoUnavail (%d)", got, PAMAuthInfoUnavail)
			}
		})
	}
}

// An over-long session_id would not survive the round trip (the broker's own
// validator caps it at 128 bytes), so it is refused rather than truncated.
func TestPerformAuthenticationRejectsOverlongSessionID(t *testing.T) {
	t.Parallel()

	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a'
	}

	broker := newFakeBroker(t, func(_ int, _ map[string]interface{}) interface{} {
		return deviceStarted(string(long))
	})

	got := performAuthentication(broker.socketPath, "testuser", "sshd", "10.0.0.1", "ssh", 30)
	if got != PAMAuthInfoUnavail {
		t.Fatalf("over-long session_id: got PAM result %d, want PAMAuthInfoUnavail (%d)", got, PAMAuthInfoUnavail)
	}
	if n := len(broker.received()); n != 1 {
		t.Fatalf("expected no polling, got %d requests", n)
	}
}

// TestLoginTypeClassificationMatchesGo pins the C module's login-type
// classification to GetLoginType's. The broker applies per-login-type policy, so
// if pam_oidc.so and the Go client disagreed, the same login would be evaluated
// against different rules depending on which client handled it. The C side used
// to differ on both counts covered here: it matched "gdm"/"lightdm" as
// substrings but not "sddm" at all, and it tested the TTY before the service, so
// a display manager on tty1 was classified "console".
func TestLoginTypeClassificationMatchesGo(t *testing.T) {
	cases := []struct {
		service string
		tty     string
	}{
		{"sshd", "pts/0"},
		{"sshd", "tty1"},
		{"gdm", "tty1"},
		{"lightdm", "tty7"},
		{"sddm", "tty1"},
		{"gdm3", "tty1"},
		{"login", "tty1"},
		{"login", "tty"},
		{"login", "tty12"},
		{"login", "pts/0"},
		{"su", "unknown"},
		{"sudo", ""},
		{"", ""},
		{"SSHD", "pts/0"},
	}

	for _, tc := range cases {
		t.Run(tc.service+"/"+tc.tty, func(t *testing.T) {
			want := GetLoginType(tc.service, tc.tty)
			if got := classifyLoginTypeC(tc.service, tc.tty); got != want {
				t.Errorf("C classify_login_type(%q, %q) = %q, Go GetLoginType = %q",
					tc.service, tc.tty, got, want)
			}
		})
	}
}

// TestAcctMgmtHasNoOpinion pins pam_sm_acct_mgmt's return value. The module
// performs no account-phase authorization — the broker decides during the auth
// phase — so it must answer PAM_IGNORE ("no opinion"), never PAM_SUCCESS.
//
// This is a regression test for a real misconfiguration hazard: PAM_SUCCESS from a
// module marked `sufficient` short-circuits the rest of the account stack, and the
// shipped configs used `account sufficient pam_oidc.so`. Together they disabled
// every account check that followed — pam_time, pam_nologin, pam_access, account
// expiry, pam_unix's shadow checks — for every user.
func TestAcctMgmtHasNoOpinion(t *testing.T) {
	got := acctMgmtVerdict()

	if got == PAMSuccess {
		t.Fatal("pam_sm_acct_mgmt returns PAM_SUCCESS: with `account sufficient pam_oidc.so` " +
			"that short-circuits every account module after it")
	}
	if got != PAMIgnore {
		t.Errorf("pam_sm_acct_mgmt returned %d, want PAM_IGNORE (%d)", got, PAMIgnore)
	}
}
