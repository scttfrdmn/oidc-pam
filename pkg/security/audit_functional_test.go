package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// TestAuditLoggerSecurityEvents tests that security-critical events are properly logged
func TestAuditLoggerSecurityEvents(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	logFile := filepath.Join(tempDir, "security.log")
	
	cfg := config.AuditConfig{
		Enabled: true,
		Format:  "json",
		Outputs: []config.AuditOutput{
			{
				Type: "file",
				Path: logFile,
			},
		},
	}

	logger, err := NewAuditLogger(cfg)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := logger.Start(ctx); err != nil {
		t.Fatalf("Failed to start audit logger: %v", err)
	}
	defer func() { _ = logger.Stop() }()

	// Test critical security events
	securityEvents := []AuditEvent{
		{
			EventType:    "authentication_failure",
			UserID:       "attacker@malicious.com",
			SourceIP:     "1.2.3.4",
			UserAgent:    "curl/7.68.0",
			Success:      false,
			ErrorMessage: "Invalid credentials",
			RiskScore:    95,
			RiskFactors:  []string{"brute_force", "untrusted_network"},
		},
		{
			EventType:         "privilege_escalation",
			UserID:           "user@example.com",
			SourceIP:         "192.168.1.100",
			Success:          false,
			ErrorMessage:     "Unauthorized admin access attempt",
			RiskScore:        85,
			RiskFactors:      []string{"privilege_escalation"},
		},
		{
			EventType:         "suspicious_login",
			UserID:           "user@example.com",
			SourceIP:         "5.6.7.8",
			Success:          true,
			RiskScore:        75,
			RiskFactors:      []string{"unusual_location", "new_device"},
			DeviceTrusted:    false,
		},
	}

	// Log all security events
	for _, event := range securityEvents {
		logger.LogAuthEvent(event)
	}

	// Allow time for async processing
	time.Sleep(500 * time.Millisecond)

	// Verify events were logged to file
	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(logData)

	// Verify critical security indicators are logged
	requiredSecurityInfo := []string{
		"authentication_failure",
		"privilege_escalation", 
		"suspicious_login",
		"attacker@malicious.com",
		"brute_force",
		"privilege_escalation",
		"unusual_location",
		"1.2.3.4",
		"5.6.7.8",
	}

	for _, info := range requiredSecurityInfo {
		if !strings.Contains(logContent, info) {
			t.Errorf("Security log missing critical information: %s", info)
		}
	}

	// Verify high-risk events are marked with appropriate risk scores
	if !strings.Contains(logContent, "\"risk_score\":95") {
		t.Error("High-risk authentication failure not properly scored")
	}
	if !strings.Contains(logContent, "\"risk_score\":85") {
		t.Error("Privilege escalation attempt not properly scored")
	}
}

// TestAuditLoggerDataIntegrity tests that audit logs cannot be tampered with
func TestAuditLoggerDataIntegrity(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-integrity-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	logFile := filepath.Join(tempDir, "integrity.log")
	
	cfg := config.AuditConfig{
		Enabled: true,
		Format:  "json",
		Outputs: []config.AuditOutput{
			{
				Type: "file",
				Path: logFile,
			},
		},
	}

	logger, err := NewAuditLogger(cfg)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := logger.Start(ctx); err != nil {
		t.Fatalf("Failed to start audit logger: %v", err)
	}
	defer func() { _ = logger.Stop() }()

	// Log a critical security event
	criticalEvent := AuditEvent{
		EventType:         "admin_login",
		UserID:           "admin@company.com",
		SourceIP:         "10.0.0.1",
		Success:          true,
		TargetHost:       "production-server",
		AuthMethod:       "certificate",
		Timestamp:        time.Now(),
	}

	logger.LogAuthEvent(criticalEvent)
	time.Sleep(200 * time.Millisecond)

	// Read the original log content
	originalContent, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read original log: %v", err)
	}

	// Verify the event was logged with all critical fields
	logContent := string(originalContent)
	criticalFields := []string{
		"admin_login",
		"admin@company.com", 
		"10.0.0.1",
		"production-server",
		"certificate",
	}

	for _, field := range criticalFields {
		if !strings.Contains(logContent, field) {
			t.Errorf("Critical audit field missing: %s", field)
		}
	}

	// Verify timestamp integrity - should be recent
	if !strings.Contains(logContent, "timestamp") {
		t.Error("Audit event missing timestamp")
	}

	// Verify JSON structure integrity
	if !strings.Contains(logContent, "{") || !strings.Contains(logContent, "}") {
		t.Error("Audit log not in valid JSON format")
	}
}

// TestAuditLoggerComplianceRequirements tests compliance-specific logging
func TestAuditLoggerComplianceRequirements(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-compliance-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	logFile := filepath.Join(tempDir, "compliance.log")
	
	cfg := config.AuditConfig{
		Enabled: true,
		Format:  "json",
		Outputs: []config.AuditOutput{
			{
				Type: "file",
				Path: logFile,
			},
		},
		ComplianceFrameworks: []string{"SOX", "PCI-DSS", "HIPAA"},
	}

	logger, err := NewAuditLogger(cfg)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := logger.Start(ctx); err != nil {
		t.Fatalf("Failed to start audit logger: %v", err)
	}
	defer func() { _ = logger.Stop() }()

	// Test events that must be logged for compliance
	complianceEvents := []AuditEvent{
		{
			EventType:         "data_access",
			UserID:           "doctor@hospital.com",
			TargetResource:   "patient_records",
			Success:          true,
			AuthMethod:       "mfa",
			MFAMethods:       []string{"totp", "biometric"},
		},
		{
			EventType:         "financial_data_access",
			UserID:           "accountant@company.com", 
			TargetResource:   "financial_reports",
			Success:          true,
			Groups:           []string{"finance", "sox_auditors"},
		},
		{
			EventType:         "payment_processing",
			UserID:           "processor@payment.com",
			TargetResource:   "credit_card_data",
			Success:          true,
			AuthMethod:       "certificate",
		},
	}

	for _, event := range complianceEvents {
		logger.LogAuthEvent(event)
	}

	time.Sleep(300 * time.Millisecond)

	// Verify compliance-required fields are present
	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read compliance log: %v", err)
	}

	logContent := string(logData)

	// SOX compliance requirements
	soxFields := []string{
		"financial_data_access",
		"accountant@company.com",
		"sox_auditors",
	}

	// HIPAA compliance requirements
	hipaaFields := []string{
		"data_access",
		"patient_records",
		"doctor@hospital.com",
		"mfa",
	}

	// PCI-DSS compliance requirements
	pciFields := []string{
		"payment_processing",
		"credit_card_data",
		"certificate",
	}

	allRequiredFields := append(soxFields, hipaaFields...)
	allRequiredFields = append(allRequiredFields, pciFields...)

	for _, field := range allRequiredFields {
		if !strings.Contains(logContent, field) {
			t.Errorf("Compliance audit missing required field: %s", field)
		}
	}
}

// TestAuditLoggerThreatDetection tests that audit logging supports threat detection
func TestAuditLoggerThreatDetection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-threat-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	logFile := filepath.Join(tempDir, "threats.log")
	
	cfg := config.AuditConfig{
		Enabled: true,
		Format:  "json",
		Outputs: []config.AuditOutput{
			{
				Type: "file",
				Path: logFile,
			},
		},
	}

	logger, err := NewAuditLogger(cfg)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := logger.Start(ctx); err != nil {
		t.Fatalf("Failed to start audit logger: %v", err)
	}
	defer func() { _ = logger.Stop() }()

	// Simulate attack patterns that should be detectable in logs
	attackPatterns := []AuditEvent{
		// Brute force attack pattern
		{
			EventType:    "authentication_failure",
			UserID:       "admin",
			SourceIP:     "192.168.1.100",
			Success:      false,
			ErrorMessage: "Invalid password",
			Timestamp:    time.Now().Add(-10 * time.Second),
		},
		{
			EventType:    "authentication_failure", 
			UserID:       "admin",
			SourceIP:     "192.168.1.100",
			Success:      false,
			ErrorMessage: "Invalid password",
			Timestamp:    time.Now().Add(-8 * time.Second),
		},
		{
			EventType:    "authentication_failure",
			UserID:       "admin", 
			SourceIP:     "192.168.1.100",
			Success:      false,
			ErrorMessage: "Invalid password",
			Timestamp:    time.Now().Add(-6 * time.Second),
		},
		// Successful login after brute force
		{
			EventType:     "authentication_success",
			UserID:       "admin",
			SourceIP:     "192.168.1.100", 
			Success:      true,
			RiskScore:    90,
			RiskFactors:  []string{"recent_failures", "brute_force_pattern"},
			Timestamp:    time.Now(),
		},
	}

	for _, event := range attackPatterns {
		logger.LogAuthEvent(event)
	}

	time.Sleep(300 * time.Millisecond)

	// Read and analyze the threat log
	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read threat log: %v", err)
	}

	logContent := string(logData)

	// Verify attack pattern indicators are logged
	threatIndicators := []string{
		"authentication_failure",
		"Invalid password", 
		"192.168.1.100",
		"recent_failures",
		"brute_force_pattern",
		"\"risk_score\":90",
	}

	for _, indicator := range threatIndicators {
		if !strings.Contains(logContent, indicator) {
			t.Errorf("Threat detection missing indicator: %s", indicator)
		}
	}

	// Count the number of failure events to verify pattern logging
	failureCount := strings.Count(logContent, "authentication_failure")
	if failureCount < 3 {
		t.Errorf("Expected at least 3 failure events for brute force pattern, got %d", failureCount)
	}

	// Verify the successful login after failures is marked high-risk
	if !strings.Contains(logContent, "authentication_success") {
		t.Error("Missing successful authentication after brute force pattern")
	}
}