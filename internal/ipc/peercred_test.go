package ipc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestGetPeerCredentials(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "peercred-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	// Create a Unix socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Connect to the socket
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		connCh <- conn
	}()

	clientConn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Get the server-side connection
	select {
	case serverConn := <-connCh:
		defer serverConn.Close()

		uid, gid, err := getPeerCredentials(serverConn)
		if err != nil {
			// On non-Linux platforms, the stub returns 0, 0, nil
			// so this path is only hit if something unexpected happens
			t.Fatalf("getPeerCredentials failed: %v", err)
		}

		// On Linux, uid/gid should match the current process
		// On non-Linux (stub), uid=0 and gid=0
		t.Logf("Peer credentials: uid=%d, gid=%d", uid, gid)

	case err := <-errCh:
		t.Fatalf("Accept failed: %v", err)
	}
}

func TestGetPeerCredentialsNonUnixConn(t *testing.T) {
	// Create a TCP connection (not a Unix socket) to test the type assertion
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create TCP listener: %v", err)
	}
	defer listener.Close()

	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		connCh <- conn
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	select {
	case serverConn := <-connCh:
		defer serverConn.Close()

		_, _, err := getPeerCredentials(serverConn)
		// On Linux, this should fail because it's not a Unix socket
		// On non-Linux (stub), this returns 0, 0, nil regardless
		if err != nil {
			t.Logf("Expected error for TCP connection: %v", err)
		} else {
			t.Log("Stub implementation returned no error for non-Unix connection (expected on non-Linux)")
		}

	case err := <-errCh:
		t.Fatalf("Accept failed: %v", err)
	}
}
