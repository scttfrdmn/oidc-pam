package pam

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewPAMModule(t *testing.T) {
	socketPath := "/tmp/test.sock"
	debug := true
	
	module := NewPAMModule(socketPath, debug)
	
	if module.GetSocketPath() != socketPath {
		t.Errorf("Expected socket path %s, got %s", socketPath, module.GetSocketPath())
	}
	
	if !module.IsDebugEnabled() {
		t.Error("Expected debug to be enabled")
	}
}

func TestSetDebug(t *testing.T) {
	module := NewPAMModule("/tmp/test.sock", false)
	
	if module.IsDebugEnabled() {
		t.Error("Expected debug to be disabled initially")
	}
	
	module.SetDebug(true)
	
	if !module.IsDebugEnabled() {
		t.Error("Expected debug to be enabled after SetDebug(true)")
	}
}

func TestIsSocketPathValid(t *testing.T) {
	tests := []struct {
		path  string
		valid bool
	}{
		{"", false},
		{"/tmp/test.sock", true},
		{"relative/path", false},
		{"/valid/path", true},
		{"/very/long/path/that/exceeds/the/maximum/unix/domain/socket/path/length/limit/which/should/be/rejected/because/it/is/too/long/for/the/system/to/handle/properly", false},
	}
	
	for _, test := range tests {
		if IsSocketPathValid(test.path) != test.valid {
			t.Errorf("Expected IsSocketPathValid(%s) to return %v", test.path, test.valid)
		}
	}
}

func TestGetLoginType(t *testing.T) {
	tests := []struct {
		service  string
		tty      string
		expected string
	}{
		{"sshd", "pts/0", "ssh"},
		{"gdm", "tty1", "gui"},
		{"lightdm", "tty2", "gui"},
		{"login", "tty1", "console"},
		{"login", "pts/0", "unknown"},
		{"unknown", "unknown", "unknown"},
	}
	
	for _, test := range tests {
		result := GetLoginType(test.service, test.tty)
		if result != test.expected {
			t.Errorf("Expected GetLoginType(%s, %s) to return %s, got %s", 
				test.service, test.tty, test.expected, result)
		}
	}
}

func TestBuildAuthRequest(t *testing.T) {
	username := "testuser"
	service := "sshd"
	rhost := "192.168.1.100"
	tty := "pts/0"
	
	req := BuildAuthRequest(username, service, rhost, tty)
	
	if req.Type != "authenticate" {
		t.Errorf("Expected type 'authenticate', got %s", req.Type)
	}
	
	if req.UserID != username {
		t.Errorf("Expected user_id %s, got %s", username, req.UserID)
	}
	
	if req.LoginType != "ssh" {
		t.Errorf("Expected login_type 'ssh', got %s", req.LoginType)
	}
	
	if req.TargetHost != rhost {
		t.Errorf("Expected target_host %s, got %s", rhost, req.TargetHost)
	}
	
	if req.Metadata["service"] != service {
		t.Errorf("Expected service %s in metadata, got %s", service, req.Metadata["service"])
	}
	
	if req.Metadata["tty"] != tty {
		t.Errorf("Expected tty %s in metadata, got %s", tty, req.Metadata["tty"])
	}
}

func TestSerializeAuthRequest(t *testing.T) {
	req := &AuthRequest{
		Type:       "authenticate",
		UserID:     "testuser",
		LoginType:  "ssh",
		TargetHost: "192.168.1.100",
		Metadata: map[string]string{
			"service": "sshd",
			"tty":     "pts/0",
		},
	}
	
	data, err := SerializeAuthRequest(req)
	if err != nil {
		t.Fatalf("Failed to serialize auth request: %v", err)
	}
	
	if len(data) == 0 {
		t.Error("Expected serialized data to be non-empty")
	}
	
	// Check if it contains expected fields
	dataStr := string(data)
	expectedFields := []string{
		"authenticate",
		"testuser",
		"ssh",
		"192.168.1.100",
		"sshd",
		"pts/0",
	}
	
	for _, field := range expectedFields {
		if !contains(dataStr, field) {
			t.Errorf("Expected serialized data to contain %s", field)
		}
	}
}

func TestAuthResponse(t *testing.T) {
	response := &AuthResponse{
		Success:        true,
		RequiresDevice: false,
		Instructions:   "Login successful",
		SessionID:      "session123",
	}
	
	if !response.Success {
		t.Error("Expected success to be true")
	}
	
	if response.RequiresDevice {
		t.Error("Expected requires_device to be false")
	}
	
	if response.Instructions != "Login successful" {
		t.Errorf("Expected instructions 'Login successful', got %s", response.Instructions)
	}
	
	if response.SessionID != "session123" {
		t.Errorf("Expected session_id 'session123', got %s", response.SessionID)
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr || 
		   len(s) >= len(substr) && s[:len(substr)] == substr ||
		   len(s) > len(substr) && containsMiddle(s, substr)
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark tests
func BenchmarkBuildAuthRequest(b *testing.B) {
	username := "testuser"
	service := "sshd"
	rhost := "192.168.1.100"
	tty := "pts/0"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildAuthRequest(username, service, rhost, tty)
	}
}

func BenchmarkSerializeAuthRequest(b *testing.B) {
	req := &AuthRequest{
		Type:       "authenticate",
		UserID:     "testuser",
		LoginType:  "ssh",
		TargetHost: "192.168.1.100",
		Metadata: map[string]string{
			"service": "sshd",
			"tty":     "pts/0",
		},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SerializeAuthRequest(req)
	}
}

func BenchmarkGetLoginType(b *testing.B) {
	service := "sshd"
	tty := "pts/0"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetLoginType(service, tty)
	}
}

// Additional comprehensive tests for PAM module functionality

func TestPAMModuleSocketConnections(t *testing.T) {
	// Test invalid socket path scenarios
	module := NewPAMModule("", true)
	
	// Test authentication with invalid socket path
	err := module.AuthenticateUser("testuser", "sshd", "127.0.0.1", "pts/0")
	if err == nil {
		t.Error("Expected error for empty socket path")
	}
	
	// Test with non-existent socket path
	module = NewPAMModule("/non/existent/socket.sock", true)
	err = module.AuthenticateUser("testuser", "sshd", "127.0.0.1", "pts/0")
	if err == nil {
		t.Error("Expected error for non-existent socket path")
	}
}

func TestPAMModuleLogging(t *testing.T) {
	module := NewPAMModule("/tmp/test.sock", true)
	
	// Test logging functionality (should not panic)
	module.LogMessage(1, "Test log message")
	module.LogMessage(2, "Test warning message")
	module.LogMessage(3, "Test error message")
	
	// Test with empty message
	module.LogMessage(1, "")
	
	// Test with long message
	longMessage := strings.Repeat("Long message content ", 100)
	module.LogMessage(1, longMessage)
}

func TestConnectToBrokerErrors(t *testing.T) {
	// Test connection with invalid socket paths
	testPaths := []string{
		"",
		"/non/existent/path.sock",
		"/tmp/not_a_socket",
		"relative/path.sock",
	}
	
	for _, path := range testPaths {
		sock, err := ConnectToBroker(path)
		if err == nil {
			t.Errorf("Expected error for invalid socket path: %s", path)
			CloseSocket(sock) // Clean up if somehow successful
		}
	}
}

func TestSocketOperations(t *testing.T) {
	// Test CloseSocket with invalid socket descriptors
	// These should not panic
	CloseSocket(-1)
	CloseSocket(0)
	CloseSocket(999999)
}

func TestSendAuthRequestErrors(t *testing.T) {
	// Test with invalid socket descriptors
	invalidSockets := []int{-1, 0, 999999}
	
	for _, sock := range invalidSockets {
		err := SendAuthRequest(sock, "testuser", "sshd", "127.0.0.1", "pts/0")
		if err == nil {
			t.Errorf("Expected error for invalid socket descriptor: %d", sock)
		}
	}
}

func TestReceiveAuthResponseErrors(t *testing.T) {
	// Test with invalid socket descriptors
	invalidSockets := []int{-1, 0, 999999}
	
	for _, sock := range invalidSockets {
		response, err := ReceiveAuthResponse(sock)
		if err == nil {
			t.Errorf("Expected error for invalid socket descriptor: %d", sock)
		}
		if response != nil {
			t.Errorf("Expected nil response for invalid socket descriptor: %d", sock)
		}
	}
}

func TestLogPAMMessagePriorities(t *testing.T) {
	// Test different priority levels
	priorities := []int{0, 1, 2, 3, 4, 5, 6, 7}
	
	for _, priority := range priorities {
		// Should not panic
		LogPAMMessage(priority, "Test message with priority level")
	}
	
	// Test with negative priority
	LogPAMMessage(-1, "Test message with negative priority")
	
	// Test with high priority
	LogPAMMessage(100, "Test message with high priority")
}

func TestAuthRequestSerialization(t *testing.T) {
	// Test serialization of complex auth request
	req := &AuthRequest{
		Type:       "authenticate",
		UserID:     "complex_user@domain.com",
		LoginType:  "ssh",
		TargetHost: "192.168.1.100",
		Metadata: map[string]string{
			"service":     "sshd",
			"tty":         "pts/0",
			"pid":         "12345",
			"client_addr": "10.0.0.1",
			"client_port": "56789",
		},
	}
	
	data, err := SerializeAuthRequest(req)
	if err != nil {
		t.Fatalf("Failed to serialize complex auth request: %v", err)
	}
	
	// Verify it can be deserialized
	var deserializedReq AuthRequest
	err = json.Unmarshal(data, &deserializedReq)
	if err != nil {
		t.Fatalf("Failed to deserialize auth request: %v", err)
	}
	
	// Verify all fields are preserved
	if deserializedReq.Type != req.Type {
		t.Errorf("Type mismatch: expected %s, got %s", req.Type, deserializedReq.Type)
	}
	if deserializedReq.UserID != req.UserID {
		t.Errorf("UserID mismatch: expected %s, got %s", req.UserID, deserializedReq.UserID)
	}
	if deserializedReq.LoginType != req.LoginType {
		t.Errorf("LoginType mismatch: expected %s, got %s", req.LoginType, deserializedReq.LoginType)
	}
	if deserializedReq.TargetHost != req.TargetHost {
		t.Errorf("TargetHost mismatch: expected %s, got %s", req.TargetHost, deserializedReq.TargetHost)
	}
	if len(deserializedReq.Metadata) != len(req.Metadata) {
		t.Errorf("Metadata length mismatch: expected %d, got %d", len(req.Metadata), len(deserializedReq.Metadata))
	}
}

func TestAuthRequestSerializationErrors(t *testing.T) {
	// Test serialization with nil request
	data, err := SerializeAuthRequest(nil)
	if err != nil {
		t.Logf("Serialization of nil request failed as expected: %v", err)
	}
	if data != nil && string(data) != "null" {
		t.Error("Expected null serialization for nil request")
	}
}

func TestAuthResponseStructure(t *testing.T) {
	// Test various auth response configurations
	responses := []*AuthResponse{
		{
			Success:        true,
			RequiresDevice: false,
			Instructions:   "Authentication successful",
			SessionID:      "session-123",
		},
		{
			Success:        false,
			RequiresDevice: true,
			Instructions:   "Please complete device authentication",
			ErrorMessage:   "Device authentication required",
		},
		{
			Success:      false,
			ErrorMessage: "Invalid credentials",
		},
		{
			Success:        true,
			RequiresDevice: false,
			Instructions:   "",
			SessionID:      "",
		},
	}
	
	for i, response := range responses {
		// Test JSON serialization/deserialization
		data, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("Failed to serialize response %d: %v", i, err)
		}
		
		var deserializedResponse AuthResponse
		err = json.Unmarshal(data, &deserializedResponse)
		if err != nil {
			t.Fatalf("Failed to deserialize response %d: %v", i, err)
		}
		
		// Verify fields match
		if deserializedResponse.Success != response.Success {
			t.Errorf("Response %d: Success mismatch", i)
		}
		if deserializedResponse.RequiresDevice != response.RequiresDevice {
			t.Errorf("Response %d: RequiresDevice mismatch", i)
		}
		if deserializedResponse.Instructions != response.Instructions {
			t.Errorf("Response %d: Instructions mismatch", i)
		}
		if deserializedResponse.ErrorMessage != response.ErrorMessage {
			t.Errorf("Response %d: ErrorMessage mismatch", i)
		}
		if deserializedResponse.SessionID != response.SessionID {
			t.Errorf("Response %d: SessionID mismatch", i)
		}
	}
}

func TestGetLoginTypeEdgeCases(t *testing.T) {
	// Test edge cases for GetLoginType
	testCases := []struct {
		service  string
		tty      string
		expected string
	}{
		// Service variations
		{"SSHD", "pts/0", "unknown"},      // Case sensitivity
		{"SSH", "pts/0", "unknown"},       // Different SSH variant
		{"openssh", "pts/0", "unknown"},   // Different SSH variant
		{"gdm3", "tty1", "console"},       // GDM variant (tty1 -> console)
		{"sddm", "tty1", "gui"},           // SDDM (additional GUI)
		
		// TTY variations
		{"login", "tty", "console"},       // Incomplete TTY but starts with tty
		{"login", "tty1", "console"},      // Console TTY
		{"login", "tty12", "console"},     // Multi-digit TTY
		{"login", "ttys0", "console"},     // Serial TTY
		{"login", "console", "unknown"},   // Console but not tty format
		
		// Edge cases
		{"", "", "unknown"},               // Empty inputs
		{"unknown-service", "pts/0", "unknown"},
		{"login", "unknown-tty", "unknown"},
		{"service", "ty1", "unknown"},     // Malformed TTY
		
		// Boundary conditions
		{"a", "b", "unknown"},             // Single character inputs
		{strings.Repeat("a", 100), "pts/0", "unknown"}, // Long service name
		{"login", strings.Repeat("t", 100), "unknown"}, // Long TTY name
	}
	
	for _, tc := range testCases {
		result := GetLoginType(tc.service, tc.tty)
		if result != tc.expected {
			t.Errorf("GetLoginType(%q, %q) = %q, expected %q", 
				tc.service, tc.tty, result, tc.expected)
		}
	}
}

func TestIsSocketPathValidEdgeCases(t *testing.T) {
	// Test additional edge cases for socket path validation
	testCases := []struct {
		path     string
		expected bool
		name     string
	}{
		{"/", true, "root path"},
		{"/a", true, "single character path"},
		{"/tmp/", true, "directory path"},
		{"/tmp/.hidden", true, "hidden file"},
		{"/tmp/socket with spaces", true, "path with spaces"},
		{"/tmp/socket\nwith\nnewlines", true, "path with newlines"},
		{"/tmp/socket\twith\ttabs", true, "path with tabs"},
		{"//double//slash", true, "double slashes"},
		{"/tmp/" + strings.Repeat("a", 102), true, "exactly 107 chars"},
		{"/tmp/" + strings.Repeat("a", 103), false, "108 chars (too long)"},
		{strings.Repeat("/a", 54), false, "very long path (108 chars)"},
	}
	
	for _, tc := range testCases {
		result := IsSocketPathValid(tc.path)
		if result != tc.expected {
			t.Errorf("IsSocketPathValid(%q) = %v, expected %v (%s)", 
				tc.path, result, tc.expected, tc.name)
		}
	}
}

func TestBuildAuthRequestMetadata(t *testing.T) {
	// Test that BuildAuthRequest properly includes metadata
	req := BuildAuthRequest("user", "sshd", "host", "pts/0")
	
	if req.Metadata == nil {
		t.Fatal("Expected metadata to be non-nil")
	}
	
	expectedKeys := []string{"service", "tty", "pid"}
	for _, key := range expectedKeys {
		if _, exists := req.Metadata[key]; !exists {
			t.Errorf("Expected metadata key %s to exist", key)
		}
	}
	
	// Verify specific metadata values
	if req.Metadata["service"] != "sshd" {
		t.Errorf("Expected service 'sshd', got %s", req.Metadata["service"])
	}
	if req.Metadata["tty"] != "pts/0" {
		t.Errorf("Expected tty 'pts/0', got %s", req.Metadata["tty"])
	}
	
	// PID should be a valid number
	if req.Metadata["pid"] == "" || req.Metadata["pid"] == "0" {
		t.Errorf("Expected valid PID, got %s", req.Metadata["pid"])
	}
}

// Test concurrent access to PAM module functions
func TestPAMModuleConcurrency(t *testing.T) {
	module := NewPAMModule("/tmp/test.sock", true)
	
	// Test concurrent access to debug setting
	done := make(chan bool, 10)
	
	for i := 0; i < 10; i++ {
		go func(i int) {
			defer func() { done <- true }()
			
			// Toggle debug mode
			module.SetDebug(i%2 == 0)
			
			// Check debug status
			_ = module.IsDebugEnabled()
			
			// Get socket path
			_ = module.GetSocketPath()
			
			// Log a message
			module.LogMessage(1, "Concurrent test message")
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}