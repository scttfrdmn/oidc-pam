package ipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/auth"
)

// createTestBroker creates a minimal broker for testing
func createTestBroker(t *testing.T) *auth.Broker {
	// Return nil for simple tests since the IPC server should handle nil broker gracefully
	return nil
}

func TestNewServer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)

	server, err := NewServer(socketPath, broker)
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
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker)
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
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker)
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
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker)
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
	// Test with invalid socket path
	invalidPath := "/invalid/path/that/does/not/exist/test.sock"
	broker := createTestBroker(t)
	server, err := NewServer(invalidPath, broker)
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
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker)
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
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start and stop server
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	go func() {
		server.Start(ctx)
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
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	broker := createTestBroker(t)
	server, err := NewServer(socketPath, broker)
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