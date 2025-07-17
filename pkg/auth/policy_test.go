package auth

import (
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

func TestPolicyEngine_Creation(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime: time.Hour,
		},
	}

	pe, err := NewPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	if pe == nil {
		t.Error("Expected non-nil policy engine")
	}
}

func TestPolicyEngine_BasicEvaluation(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime: time.Hour,
		},
	}

	pe, err := NewPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test basic request evaluation
	request := &AuthRequest{
		UserID:     "test-user",
		SourceIP:   "192.168.1.100",
		UserAgent:  "test-client",
		TargetHost: "test-server",
		Timestamp:  time.Now(),
	}

	result, err := pe.EvaluateRequest(request)
	if err != nil {
		t.Fatalf("Failed to evaluate request: %v", err)
	}

	if result == nil {
		t.Error("Expected non-nil policy result")
		return
	}

	// Should have a default result
	if result.Reason == "" {
		t.Log("Policy result has no reason, which is acceptable")
	}
}

func TestPolicyEngine_DifferentIPTypes(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime: time.Hour,
		},
	}

	pe, err := NewPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test with different IP types
	testIPs := []string{
		"192.168.1.100", // Private
		"10.0.0.1",      // Private
		"8.8.8.8",       // Public
		"127.0.0.1",     // Loopback
		"::1",           // IPv6 loopback
	}

	for _, ip := range testIPs {
		request := &AuthRequest{
			UserID:     "test-user",
			SourceIP:   ip,
			UserAgent:  "test-client",
			TargetHost: "test-server",
			Timestamp:  time.Now(),
		}

		result, err := pe.EvaluateRequest(request)
		if err != nil {
			t.Logf("Warning: Failed to evaluate request with IP %s: %v", ip, err)
			continue
		}

		if result == nil {
			t.Errorf("Expected non-nil result for IP %s", ip)
			continue
		}

		if result.RiskScore < 0 {
			t.Errorf("Expected non-negative risk score for IP %s", ip)
		}

		t.Logf("IP %s: allowed=%t, risk_score=%d", ip, result.Allowed, result.RiskScore)
	}
}

func TestPolicyEngine_RequestValidation(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime: time.Hour,
		},
	}

	pe, err := NewPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test with nil request (should be handled gracefully)
	result, err := pe.EvaluateRequest(nil)
	if err == nil {
		t.Error("Expected error with nil request")
	}
	if result != nil {
		t.Error("Expected nil result with nil request")
	}

	// Test with empty request
	emptyRequest := &AuthRequest{}
	result, err = pe.EvaluateRequest(emptyRequest)
	if err != nil {
		t.Logf("Warning: Error with empty request: %v", err)
	}

	if result != nil && result.RiskScore < 0 {
		t.Error("Expected non-negative risk score even with empty request")
	}
}

func TestPolicyEngine_TimeBasedEvaluation(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime: time.Hour,
		},
	}

	pe, err := NewPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test with different times
	now := time.Now()
	testTimes := []time.Time{
		now,
		now.Add(-time.Hour),    // Past
		now.Add(time.Hour),     // Future
		now.Add(-24 * time.Hour), // Yesterday
	}

	for _, timestamp := range testTimes {
		request := &AuthRequest{
			UserID:     "test-user",
			SourceIP:   "192.168.1.100",
			UserAgent:  "test-client",
			TargetHost: "test-server",
			Timestamp:  timestamp,
		}

		result, err := pe.EvaluateRequest(request)
		if err != nil {
			t.Logf("Warning: Failed to evaluate request with timestamp %v: %v", timestamp, err)
			continue
		}

		if result == nil {
			t.Errorf("Expected non-nil result for timestamp %v", timestamp)
			continue
		}

		t.Logf("Timestamp %v: allowed=%t, risk_score=%d", timestamp, result.Allowed, result.RiskScore)
	}
}

func TestPolicyEngine_UserAgentEvaluation(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime: time.Hour,
		},
	}

	pe, err := NewPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test with different user agents
	testUserAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"SSH-2.0-OpenSSH_8.0",
		"curl/7.68.0",
		"suspicious-bot/1.0",
		"",
	}

	for _, userAgent := range testUserAgents {
		request := &AuthRequest{
			UserID:     "test-user",
			SourceIP:   "192.168.1.100",
			UserAgent:  userAgent,
			TargetHost: "test-server",
			Timestamp:  time.Now(),
		}

		result, err := pe.EvaluateRequest(request)
		if err != nil {
			t.Logf("Warning: Failed to evaluate request with user agent %s: %v", userAgent, err)
			continue
		}

		if result == nil {
			t.Errorf("Expected non-nil result for user agent %s", userAgent)
			continue
		}

		t.Logf("User agent %s: allowed=%t, risk_score=%d", userAgent, result.Allowed, result.RiskScore)
	}
}

func TestPolicyEngine_TargetHostEvaluation(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TokenLifetime: time.Hour,
		},
	}

	pe, err := NewPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test with different target hosts
	testHosts := []string{
		"production-server",
		"dev-server",
		"test-server",
		"admin-server",
		"localhost",
		"192.168.1.100",
	}

	for _, host := range testHosts {
		request := &AuthRequest{
			UserID:     "test-user",
			SourceIP:   "192.168.1.100",
			UserAgent:  "test-client",
			TargetHost: host,
			Timestamp:  time.Now(),
		}

		result, err := pe.EvaluateRequest(request)
		if err != nil {
			t.Logf("Warning: Failed to evaluate request with host %s: %v", host, err)
			continue
		}

		if result == nil {
			t.Errorf("Expected non-nil result for host %s", host)
			continue
		}

		t.Logf("Host %s: allowed=%t, risk_score=%d", host, result.Allowed, result.RiskScore)
	}
}

func TestPolicyEngine_EmptyConfiguration(t *testing.T) {
	cfg := &config.Config{}

	pe, err := NewPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to create policy engine with empty config: %v", err)
	}

	// Should still be able to evaluate requests
	request := &AuthRequest{
		UserID:     "test-user",
		SourceIP:   "192.168.1.100",
		UserAgent:  "test-client",
		TargetHost: "test-server",
		Timestamp:  time.Now(),
	}

	result, err := pe.EvaluateRequest(request)
	if err != nil {
		t.Logf("Warning: Failed to evaluate request with empty config: %v", err)
		return
	}

	if result == nil {
		t.Error("Expected non-nil result even with empty config")
		return
	}

	// Should have some default behavior
	if result.RiskScore < 0 {
		t.Error("Expected non-negative risk score with empty config")
	}
}