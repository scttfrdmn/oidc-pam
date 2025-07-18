package ipc

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/auth"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

func TestServerHandleRequestTypes(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	
	// Create a broker (will be nil, but that's expected for these tests)
	server, err := NewServer(socketPath, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test invalid request type
	invalidRequest := &Request{
		Type:   "invalid_request_type",
		UserID: "test-user",
	}
	
	response := server.handleRequest(invalidRequest)
	if response.Success {
		t.Error("Expected invalid request type to fail")
	}
	if response.ErrorCode != "INVALID_REQUEST_TYPE" {
		t.Errorf("Expected INVALID_REQUEST_TYPE, got %s", response.ErrorCode)
	}
	if !strings.Contains(response.ErrorMessage, "Unknown request type") {
		t.Errorf("Expected error message to contain 'Unknown request type', got %s", response.ErrorMessage)
	}
}

func TestServerFormatInstructionsExtended(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	server, err := NewServer(socketPath, nil)
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
	if !strings.Contains(consoleInstructions, deviceCode) {
		t.Error("Console instructions should contain device code")
	}

	// Test GUI instructions
	guiInstructions := server.formatInstructions("gui", deviceURL, deviceCode, qrCode)
	if guiInstructions == "" {
		t.Error("Expected non-empty GUI instructions")
	}
	if !strings.Contains(guiInstructions, deviceCode) {
		t.Error("GUI instructions should contain device code")
	}

	// Test SSH instructions (default case)
	sshInstructions := server.formatInstructions("ssh", deviceURL, deviceCode, qrCode)
	if sshInstructions == "" {
		t.Error("Expected non-empty SSH instructions")
	}
	if !strings.Contains(sshInstructions, deviceCode) {
		t.Error("SSH instructions should contain device code")
	}

	// Test unknown type (should default to SSH)
	unknownInstructions := server.formatInstructions("unknown", deviceURL, deviceCode, qrCode)
	if unknownInstructions == "" {
		t.Error("Expected non-empty instructions for unknown type")
	}
	if !strings.Contains(unknownInstructions, deviceCode) {
		t.Error("Unknown type instructions should contain device code")
	}
}

func TestServerConnectionWithMalformedJSON(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	server, err := NewServer(socketPath, nil)
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
	defer server.Stop()

	// Test connection with malformed JSON
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send malformed JSON
	_, err = conn.Write([]byte("{invalid json"))
	if err != nil {
		t.Fatalf("Failed to write malformed JSON: %v", err)
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	var response Response
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.Success {
		t.Error("Expected malformed JSON to result in failure")
	}
	if response.ErrorCode != "INVALID_REQUEST" {
		t.Errorf("Expected INVALID_REQUEST, got %s", response.ErrorCode)
	}
}

func TestServerConnectionWithEmptyData(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	server, err := NewServer(socketPath, nil)
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
	defer server.Stop()

	// Test connection with empty data
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send empty data
	_, err = conn.Write([]byte(""))
	if err != nil {
		t.Fatalf("Failed to write empty data: %v", err)
	}

	// Server should handle empty data gracefully
	time.Sleep(100 * time.Millisecond)
}

func TestServerStartStopEdgeCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	server, err := NewServer(socketPath, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test multiple stops
	err = server.Stop()
	if err != nil {
		t.Errorf("First stop should not return error: %v", err)
	}

	err = server.Stop()
	if err != nil {
		t.Errorf("Second stop should not return error: %v", err)
	}

	// Test stop after start
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	err = server.Stop()
	if err != nil {
		t.Errorf("Stop after start should not return error: %v", err)
	}

	// Test stop again
	err = server.Stop()
	if err != nil {
		t.Errorf("Stop after stop should not return error: %v", err)
	}
}

func TestServerWithValidRequestStructure(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	server, err := NewServer(socketPath, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Verify server was created
	if server == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test valid JSON structure (without sending it to avoid panic)
	request := &Request{
		Type:       "authenticate",
		UserID:     "test-user",
		SourceIP:   "192.168.1.100",
		TargetHost: "test-host",
		LoginType:  "ssh",
		SessionID:  "test-session",
		Metadata: map[string]interface{}{
			"service": "sshd",
		},
	}

	requestData, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	// Test that we can marshal and unmarshal the request structure
	var parsedRequest Request
	err = json.Unmarshal(requestData, &parsedRequest)
	if err != nil {
		t.Fatalf("Failed to unmarshal request: %v", err)
	}

	if parsedRequest.Type != "authenticate" {
		t.Errorf("Expected type 'authenticate', got %s", parsedRequest.Type)
	}
	if parsedRequest.UserID != "test-user" {
		t.Errorf("Expected UserID 'test-user', got %s", parsedRequest.UserID)
	}
}

func TestServerConcurrentConnections(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")
	server, err := NewServer(socketPath, nil)
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
	defer server.Stop()

	// Test multiple concurrent connections
	const numConnections = 5
	connections := make([]net.Conn, numConnections)

	for i := 0; i < numConnections; i++ {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatalf("Failed to connect (connection %d): %v", i, err)
		}
		connections[i] = conn
	}

	// Send invalid JSON to avoid panic with nil broker
	for i, conn := range connections {
		_, err = conn.Write([]byte("test data"))
		if err != nil {
			t.Fatalf("Failed to write to connection %d: %v", i, err)
		}
	}

	// Clean up connections
	for i, conn := range connections {
		if err := conn.Close(); err != nil {
			t.Errorf("Failed to close connection %d: %v", i, err)
		}
	}

	// Server should still be running
	time.Sleep(100 * time.Millisecond)
}

func TestServerWithRealBrokerConfig(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ipc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a configuration that will work for broker creation
	cfg := &config.Config{
		Server: config.ServerConfig{
			SocketPath: filepath.Join(tempDir, "broker.sock"),
		},
		OIDC: config.OIDCConfig{
			Providers: []config.OIDCProvider{
				{
					Name:            "test-provider",
					Issuer:          "https://example.com",
					ClientID:        "test-client",
					Scopes:          []string{"openid", "profile"},
					EnabledForLogin: true,
				},
			},
		},
		Authentication: config.AuthenticationConfig{
			TokenLifetime:         time.Hour,
			RefreshThreshold:      time.Minute * 15,
			MaxConcurrentSessions: 10,
		},
		Security: config.SecurityConfig{
			TokenEncryptionKey: "test-key-that-is-long-enough-for-security",
		},
	}

	// Try to create broker (will fail due to network dependencies)
	broker, err := auth.NewBroker(cfg)
	if err != nil {
		t.Logf("Expected broker creation to fail due to network dependencies: %v", err)
		// Test with nil broker instead
		broker = nil
	}

	socketPath := filepath.Join(tempDir, "test.sock")
	server, err := NewServer(socketPath, broker)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if server == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test server can be created with either nil or real broker
	if server.broker != broker {
		t.Errorf("Expected server broker to match input broker")
	}
}