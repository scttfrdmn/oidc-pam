package security

import (
	"encoding/json"
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