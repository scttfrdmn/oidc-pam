package ipc

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/auth"
)

// createTestBroker creates a minimal broker for testing
func createTestBroker(t *testing.T) *auth.Broker {
	// Return nil for simple tests since the IPC server should handle nil broker gracefully
	return nil
}

// authResponse asserts that a handleRequest result is an authentication-shaped
// response and returns it. handleRequest returns `any` because the admin request
// types answer with their own shapes (see internal/adminapi).
func authResponse(t *testing.T, v any) *Response {
	t.Helper()
	response, ok := v.(*Response)
	if !ok {
		t.Fatalf("expected *Response, got %T", v)
	}
	return response
}

// skipIfNotRootOnLinux skips the test when running on Linux as a non-root user.
// The IPC server's verifyPeerCredentials unconditionally requires UID 0 on Linux,
// so any test that connects to the socket will be rejected when run as non-root.
func skipIfNotRootOnLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "linux" && os.Getuid() != 0 {
		t.Skip("verifyPeerCredentials requires UID 0 on Linux; skipping on non-root runner")
	}
}

func TestNewServer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)

	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	if server == nil {
		t.Fatal("Expected non-nil server")
	}
}

func TestServerLifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test start
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test that socket exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("Expected socket file to exist after start")
	}

	// Test stop
	if err := server.Stop(); err != nil {
		t.Errorf("Expected no error on stop: %v", err)
	}

	// Wait for server to finish
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			t.Errorf("Server returned unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("Server did not stop within timeout")
	}
}

func TestServerConnection(t *testing.T) {
	skipIfNotRootOnLinux(t)
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	defer func() { _ = server.Stop() }()

	// Test connection
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Write test data
	testData := []byte("test message")
	if _, err := conn.Write(testData); err != nil {
		t.Errorf("Failed to write data: %v", err)
	}

	// Test that connection is handled (server should not crash)
	time.Sleep(100 * time.Millisecond)
}

func TestServerMultipleConnections(t *testing.T) {
	skipIfNotRootOnLinux(t)
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	defer func() { _ = server.Stop() }()

	// Test multiple simultaneous connections
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatalf("Failed to connect (connection %d): %v", i, err)
		}
		conns = append(conns, conn)
	}

	// Clean up connections
	for _, conn := range conns {
		_ = conn.Close()
	}

	// Server should still be running
	time.Sleep(100 * time.Millisecond)
}

func TestServerInvalidSocketPath(t *testing.T) {
	// Use a path whose parent is a regular file: MkdirAll then fails with
	// ENOTDIR for any uid. A merely non-existent directory is not enough —
	// running as root (as the container-based `make verify-linux` does) it
	// would simply be created.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("Failed to create blocking file: %v", err)
	}
	invalidPath := filepath.Join(blocker, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(invalidPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = server.Start(ctx)
	if err == nil {
		t.Error("Expected error with invalid socket path")
		_ = server.Stop()
	}
}

func TestServerStopBeforeStart(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test stop before start (should not panic)
	err = server.Stop()
	if err != nil {
		t.Errorf("Stop before start returned error: %v", err)
	}
}

func TestServerDoubleStop(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start and stop server
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// First stop
	if err := server.Stop(); err != nil {
		t.Errorf("First stop returned error: %v", err)
	}

	// Second stop (should not panic or error)
	if err := server.Stop(); err != nil {
		t.Errorf("Second stop returned error: %v", err)
	}
}

func TestServerConnectionHandling(t *testing.T) {
	skipIfNotRootOnLinux(t)
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	defer func() { _ = server.Stop() }()

	// Connect and verify connection is handled
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Server should handle the connection without crashing
	time.Sleep(100 * time.Millisecond)

	// Verify server is still running by attempting another connection
	conn2, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Error("Server should still be running and accepting connections")
	} else {
		_ = conn2.Close()
	}
}

func TestServerHandleRequest(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test invalid request type
	invalidRequest := &Request{
		Type:   "invalid_type",
		UserID: "test-user",
	}

	response := authResponse(t, server.handleRequest(invalidRequest))
	if response.Success {
		t.Error("Expected failure for invalid request type")
	}
	if response.ErrorCode != "INVALID_REQUEST_TYPE" {
		t.Errorf("Expected error code INVALID_REQUEST_TYPE, got %s", response.ErrorCode)
	}
}

func TestServerHandleRequestUnknownTypeDoesNotEcho(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test that unknown request type is not echoed back in the response
	request := &Request{
		Type:   "secret_internal_type",
		UserID: "test-user",
	}

	response := authResponse(t, server.handleRequest(request))
	if response.Success {
		t.Error("Expected failure for unknown request type")
	}
	if response.ErrorCode != "INVALID_REQUEST_TYPE" {
		t.Errorf("Expected error code INVALID_REQUEST_TYPE, got %s", response.ErrorCode)
	}
	if strings.Contains(response.ErrorMessage, "secret_internal_type") {
		t.Errorf("Response should not echo back the unknown request type, got: %s", response.ErrorMessage)
	}
	if response.ErrorMessage != "Invalid request type" {
		t.Errorf("Expected generic error message 'Invalid request type', got: %s", response.ErrorMessage)
	}
}

func TestServerHandleAuthenticate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test authentication request (will fail due to nil broker, but tests the method)
	authRequest := &Request{
		Type:       "authenticate",
		UserID:     "test-user",
		SourceIP:   "192.168.1.100",
		UserAgent:  "test-agent",
		TargetHost: "test-host",
		LoginType:  "ssh",
		DeviceID:   "test-device",
		SessionID:  "test-session",
	}

	// This should panic with nil broker, which is expected behavior
	// We'll test this with proper error handling
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic with nil broker")
		}
	}()

	_ = server.handleAuthenticate(authRequest)
}

func TestServerHandleCheckSession(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test session check request
	sessionRequest := &Request{
		Type:      "check_session",
		SessionID: "test-session",
	}

	// This should panic with nil broker, which is expected behavior
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic with nil broker")
		}
	}()

	_ = server.handleCheckSession(sessionRequest)
}

func TestServerHandleRefreshSession(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test session refresh request
	refreshRequest := &Request{
		Type:      "refresh_session",
		SessionID: "test-session",
	}

	// This should panic with nil broker, which is expected behavior
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic with nil broker")
		}
	}()

	_ = server.handleRefreshSession(refreshRequest)
}

func TestServerHandleRevokeSession(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test session revocation request
	revokeRequest := &Request{
		Type:      "revoke_session",
		SessionID: "test-session",
	}

	// This should panic with nil broker, which is expected behavior
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic with nil broker")
		}
	}()

	_ = server.handleRevokeSession(revokeRequest)
}

func TestServerRejectsPathTraversal(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("verifyPeerCredentials requires Linux + root; skipping path traversal test")
	}
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	defer func() { _ = server.Stop() }()

	// Connect and send a request with path traversal in UserID
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send a path traversal authenticate request
	reqJSON := `{"type":"authenticate","user_id":"../../root"}` + "\n"
	if _, err := conn.Write([]byte(reqJSON)); err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	response := string(buf[:n])
	if !strings.Contains(response, "INVALID_REQUEST") {
		t.Errorf("Expected INVALID_REQUEST error code in response, got: %s", response)
	}
	// Verify generic message is returned, not internal validation details
	if !strings.Contains(response, "Invalid request") {
		t.Errorf("Expected generic 'Invalid request' message, got: %s", response)
	}
	if strings.Contains(response, "invalid characters") {
		t.Errorf("Response should not contain internal validation details, got: %s", response)
	}
	if strings.Contains(response, "../../root") {
		t.Errorf("Response should not echo back the malicious input, got: %s", response)
	}
}

func TestServerFormatInstructions(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	deviceURL := "https://example.com/device"
	deviceCode := "ABC123"
	qrCode := "sample-qr-code"

	// Test console instructions
	consoleInstructions := server.formatInstructions("console", deviceURL, deviceCode, qrCode)
	if consoleInstructions == "" {
		t.Error("Expected non-empty console instructions")
	}

	// Test GUI instructions
	guiInstructions := server.formatInstructions("gui", deviceURL, deviceCode, qrCode)
	if guiInstructions == "" {
		t.Error("Expected non-empty GUI instructions")
	}

	// Test default (SSH) instructions
	sshInstructions := server.formatInstructions("ssh", deviceURL, deviceCode, qrCode)
	if sshInstructions == "" {
		t.Error("Expected non-empty SSH instructions")
	}

	// Test unknown login type (should default to SSH)
	unknownInstructions := server.formatInstructions("unknown", deviceURL, deviceCode, qrCode)
	if unknownInstructions == "" {
		t.Error("Expected non-empty instructions for unknown login type")
	}
}

// sendRequestOverSocket connects to the unix socket, sends a JSON request, and
// returns the decoded Response. The server may respond before the client writes
// (e.g. rate limiting), so a write error is tolerated as long as a valid
// response can still be read.
func sendRequestOverSocket(t *testing.T, socketPath string, req *Request) *Response {
	t.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}
	data = append(data, '\n')

	// Write may fail if server already closed the connection (e.g. rate limit).
	// In that case the response was already written to the socket buffer.
	_, _ = conn.Write(data)

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	return &resp
}

func TestServerRateLimitOverSocket(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("verifyPeerCredentials requires Linux + root; skipping rate limit socket test")
	}
	tempDir, err := os.MkdirTemp("", "ipc-ratelimit-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")

	// maxRequestsPerMinute=2, maxConcurrentAuths=0 (disabled), requirePeerAuth=false
	server, err := NewServer(socketPath, nil, 0660, "", false, 2, 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = server.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)
	defer func() { _ = server.Stop() }()

	req := &Request{
		Type:   "check_session",
		UserID: "test-user",
	}

	// First 2 requests should succeed (not be rate-limited — they'll fail for
	// other reasons since broker is nil, but they should NOT get RATE_LIMIT_EXCEEDED).
	for i := 0; i < 2; i++ {
		resp := sendRequestOverSocket(t, socketPath, req)
		if resp.ErrorCode == "RATE_LIMIT_EXCEEDED" {
			t.Fatalf("request %d should not have been rate-limited", i+1)
		}
	}

	// 3rd request should be rate-limited
	resp := sendRequestOverSocket(t, socketPath, req)
	if resp.ErrorCode != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("expected RATE_LIMIT_EXCEEDED on 3rd request, got error_code=%q", resp.ErrorCode)
	}
	if resp.Success {
		t.Fatal("rate-limited response should not be successful")
	}
}

func TestServerConcurrentAuthLimitOverSocket(t *testing.T) {
	skipIfNotRootOnLinux(t)
	tempDir, err := os.MkdirTemp("", "ipc-authlimit-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	socketPath := filepath.Join(tempDir, "test.sock")

	// rate limiting disabled, maxConcurrentAuths=1, no broker, requirePeerAuth=false
	server, err := NewServer(socketPath, nil, 0660, "", false, 0, 1)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test at the handleRequest level: hold one auth slot, then verify second
	// authenticate request gets TOO_MANY_CONCURRENT_AUTHS.

	// Acquire the single auth slot
	if !server.rateLimiter.AcquireAuth() {
		t.Fatal("failed to acquire initial auth slot")
	}

	req := &Request{
		Type:   "authenticate",
		UserID: "test-user",
	}

	resp := authResponse(t, server.handleRequest(req))
	if resp.ErrorCode != "TOO_MANY_CONCURRENT_AUTHS" {
		t.Fatalf("expected TOO_MANY_CONCURRENT_AUTHS, got error_code=%q", resp.ErrorCode)
	}
	if resp.Success {
		t.Fatal("response should not be successful when auth limit exceeded")
	}

	// Release the slot and verify we can acquire again
	server.rateLimiter.ReleaseAuth()
	if !server.rateLimiter.AcquireAuth() {
		t.Fatal("should be able to acquire after release")
	}
	server.rateLimiter.ReleaseAuth()
}
