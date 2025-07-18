package pam

import (
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