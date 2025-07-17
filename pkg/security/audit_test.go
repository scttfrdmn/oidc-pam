package security

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

func TestNewAuditLogger(t *testing.T) {
	tests := []struct {
		name        string
		config      config.AuditConfig
		expectError bool
	}{
		{
			name: "enabled config",
			config: config.AuditConfig{
				Enabled: true,
				Format:  "json",
				Outputs: []config.AuditOutput{
					{Type: "stdout"},
				},
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: config.AuditConfig{
				Enabled: false,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewAuditLogger(tt.config)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				if logger != nil {
					t.Error("Expected nil logger on error")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if logger == nil {
					t.Error("Expected non-nil logger")
				}
			}
		})
	}
}

func TestAuditEvent(t *testing.T) {
	event := &AuditEvent{
		EventType:    "authentication",
		UserID:       "testuser",
		Timestamp:    time.Now(),
		SourceIP:     "192.168.1.100",
		UserAgent:    "test-client",
		Success:      true,
		Provider:     "test",
		AuthMethod:   "oidc",
	}

	// Test JSON marshaling
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal audit event: %v", err)
	}

	// Test that required fields are present
	jsonStr := string(data)
	requiredFields := []string{
		"event_type", "user_id", "timestamp", "source_ip", "success",
	}

	for _, field := range requiredFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Expected JSON to contain field '%s'", field)
		}
	}

	// Test specific values are preserved
	if !strings.Contains(jsonStr, "authentication") {
		t.Error("Expected event type to be preserved")
	}
	if !strings.Contains(jsonStr, "testuser") {
		t.Error("Expected user ID to be preserved")
	}
}

func TestAuditEventFields(t *testing.T) {
	event := &AuditEvent{
		EventType:         "authentication",
		UserID:           "testuser",
		Email:            "test@example.com", 
		Groups:           []string{"admin", "users"},
		SourceIP:         "192.168.1.100",
		UserAgent:        "test-client",
		TargetHost:       "server.example.com",
		SessionID:        "session-123",
		Provider:         "test-provider",
		AuthMethod:       "oidc",
		MFAMethods:       []string{"totp"},
		Success:          true,
		RiskScore:        25,
		RiskFactors:      []string{"untrusted_network"},
		DeviceID:         "device-123",
		DeviceName:       "Test Device",
		DeviceTrusted:    false,
		NetworkPath:      []string{"router1", "router2"},
		TokenFingerprint: "abc123",
		SSHKeyFingerprint: "ssh-rsa-456",
	}

	// Test that all fields can be marshaled
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal comprehensive audit event: %v", err)
	}

	// Verify key fields are present
	jsonStr := string(data)
	expectedFields := []string{
		"event_type", "user_id", "email", "groups",
		"source_ip", "user_agent", "target_host",
		"session_id", "provider", "auth_method",
		"mfa_methods", "success", "risk_score",
		"risk_factors", "device_id", "device_name",
		"device_trusted", "network_path",
		"token_fingerprint", "ssh_key_fingerprint",
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Expected JSON to contain field '%s'", field)
		}
	}
}

func TestAuditLoggerDisabled(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: false,
	}

	logger, err := NewAuditLogger(cfg)
	if err != nil {
		t.Fatalf("Expected no error for disabled logger: %v", err)
	}

	// Test that disabled logger handles events gracefully
	event := AuditEvent{
		EventType: "test",
		UserID:    "testuser",
		Success:   true,
	}

	// Should not panic or error
	logger.LogEvent(event)
	logger.LogAuthEvent(event)
}

func TestAuditEventTimestamp(t *testing.T) {
	// Test that timestamp is properly handled
	now := time.Now()
	event := &AuditEvent{
		EventType: "test",
		UserID:    "testuser",
		Timestamp: now,
		Success:   true,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal event: %v", err)
	}

	var unmarshaled AuditEvent
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal event: %v", err)
	}

	// Verify timestamp is preserved (allowing for small precision differences)
	timeDiff := unmarshaled.Timestamp.Sub(now)
	if timeDiff > time.Second || timeDiff < -time.Second {
		t.Errorf("Timestamp not preserved correctly: expected %v, got %v", now, unmarshaled.Timestamp)
	}
}

func TestAuditEventArrayFields(t *testing.T) {
	event := &AuditEvent{
		EventType:   "test",
		UserID:      "testuser",
		Groups:      []string{"admin", "users", "developers"},
		MFAMethods:  []string{"totp", "sms"},
		RiskFactors: []string{"untrusted_network", "unusual_time"},
		NetworkPath: []string{"router1", "switch1", "server"},
		Success:     true,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal event with arrays: %v", err)
	}

	var unmarshaled AuditEvent
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal event: %v", err)
	}

	// Verify arrays are preserved
	if len(unmarshaled.Groups) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(unmarshaled.Groups))
	}
	if len(unmarshaled.MFAMethods) != 2 {
		t.Errorf("Expected 2 MFA methods, got %d", len(unmarshaled.MFAMethods))
	}
	if len(unmarshaled.RiskFactors) != 2 {
		t.Errorf("Expected 2 risk factors, got %d", len(unmarshaled.RiskFactors))
	}
}

func TestStdoutAuditOutput(t *testing.T) {
	cfg := config.AuditOutput{
		Type: "stdout",
	}

	output, err := NewStdoutAuditOutput(cfg)
	if err != nil {
		t.Fatalf("Failed to create stdout audit output: %v", err)
	}

	if output == nil {
		t.Error("Expected non-nil stdout audit output")
	}

	// Test writing events
	event := AuditEvent{
		EventType:  "test_stdout",
		UserID:     "user123",
		SourceIP:   "192.168.1.100",
		TargetHost: "server.example.com",
		Success:    true,
		Timestamp:  time.Now(),
	}

	err = output.Write(event)
	if err != nil {
		t.Errorf("Failed to write to stdout: %v", err)
	}

	// Test closing
	err = output.Close()
	if err != nil {
		t.Errorf("Failed to close stdout output: %v", err)
	}
}

func TestSyslogAuditOutput(t *testing.T) {
	cfg := config.AuditOutput{
		Type: "syslog",
	}

	output, err := NewSyslogAuditOutput(cfg)
	if err != nil {
		t.Fatalf("Failed to create syslog audit output: %v", err)
	}

	if output == nil {
		t.Error("Expected non-nil syslog audit output")
	}

	// Test writing events
	event := AuditEvent{
		EventType:  "test_syslog",
		UserID:     "user123",
		SourceIP:   "192.168.1.100",
		TargetHost: "server.example.com",
		Success:    true,
		Timestamp:  time.Now(),
	}

	err = output.Write(event)
	if err != nil {
		t.Errorf("Failed to write to syslog: %v", err)
	}

	// Test closing
	err = output.Close()
	if err != nil {
		t.Errorf("Failed to close syslog output: %v", err)
	}
}

func TestHTTPAuditOutput(t *testing.T) {
	cfg := config.AuditOutput{
		Type: "http",
		URL:  "https://example.com/audit",
	}

	output, err := NewHTTPAuditOutput(cfg)
	if err != nil {
		t.Fatalf("Failed to create HTTP audit output: %v", err)
	}

	if output == nil {
		t.Error("Expected non-nil HTTP audit output")
	}

	// Test writing events (will fail due to invalid URL, but tests the method)
	event := AuditEvent{
		EventType:  "test_http",
		UserID:     "user123",
		SourceIP:   "192.168.1.100",
		TargetHost: "server.example.com",
		Success:    true,
		Timestamp:  time.Now(),
	}

	err = output.Write(event)
	// This may fail due to network issues, but that's expected in tests
	if err != nil {
		t.Logf("HTTP write failed as expected: %v", err)
	}

	// Test closing
	err = output.Close()
	if err != nil {
		t.Errorf("Failed to close HTTP output: %v", err)
	}
}

func TestAuditOutputCreation(t *testing.T) {
	// Test creating different audit output types
	testCases := []struct {
		config       config.AuditOutput
		expectError  bool
		outputType   string
	}{
		{
			config: config.AuditOutput{
				Type: "file",
				Path: "/tmp/test-audit.log",
			},
			expectError: false,
			outputType:  "file",
		},
		{
			config: config.AuditOutput{
				Type: "stdout",
			},
			expectError: false,
			outputType:  "stdout",
		},
		{
			config: config.AuditOutput{
				Type: "syslog",
			},
			expectError: false,
			outputType:  "syslog",
		},
		{
			config: config.AuditOutput{
				Type: "http",
				URL:  "https://example.com/audit",
			},
			expectError: false,
			outputType:  "http",
		},
		{
			config: config.AuditOutput{
				Type: "unknown",
			},
			expectError: true,
			outputType:  "unknown",
		},
	}

	for _, tc := range testCases {
		t.Run("create_"+tc.outputType, func(t *testing.T) {
			var output AuditOutput
			var err error
			switch tc.config.Type {
			case "file":
				output, err = NewFileAuditOutput(tc.config)
			case "stdout":
				output, err = NewStdoutAuditOutput(tc.config)
			case "syslog":
				output, err = NewSyslogAuditOutput(tc.config)
			case "http":
				output, err = NewHTTPAuditOutput(tc.config)
			default:
				err = fmt.Errorf("unknown audit output type: %s", tc.config.Type)
			}
			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if output == nil {
					t.Error("Expected non-nil output")
				}
			}
		})
	}
}