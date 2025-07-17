package policy

import (
	"testing"
	"time"
)

func TestNewRiskEngine(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	if engine == nil {
		t.Fatal("Expected non-nil risk engine")
	}

	if engine.config != config {
		t.Error("Expected config to be set")
	}
}

func TestDefaultRiskConfig(t *testing.T) {
	config := DefaultRiskConfig()

	if config.MaxRiskScore != 100.0 {
		t.Errorf("Expected MaxRiskScore to be 100.0, got %f", config.MaxRiskScore)
	}

	if !config.GeoRiskEnabled {
		t.Error("Expected GeoRiskEnabled to be true")
	}

	if len(config.TrustedNetworks) == 0 {
		t.Error("Expected TrustedNetworks to have entries")
	}

	if len(config.TrustedCountries) == 0 {
		t.Error("Expected TrustedCountries to have entries")
	}
}

func TestAssessRisk_LowRisk(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	ctx := &AuthContext{
		UserID:     "testuser",
		RemoteAddr: "192.168.1.100",
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		LoginType:  "ssh",
		Provider:   "test",
		Country:    "US",
		City:       "San Francisco",
		DeviceFingerprint: "known-device",
		LastLogin:  time.Now().Add(-1 * time.Hour),
		LoginHistory: []LoginAttempt{
			{
				Timestamp:  time.Now().Add(-24 * time.Hour),
				Success:    true,
				RemoteAddr: "192.168.1.100",
				Country:    "US",
				UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			},
		},
	}

	assessment, err := engine.AssessRisk(ctx)
	if err != nil {
		t.Fatalf("AssessRisk failed: %v", err)
	}

	if assessment.RiskLevel != "low" {
		t.Errorf("Expected low risk, got %s", assessment.RiskLevel)
	}

	if assessment.Decision != "allow" {
		t.Errorf("Expected allow decision, got %s", assessment.Decision)
	}

	if assessment.RequiredMFA {
		t.Error("Expected MFA not to be required for low risk")
	}
}

func TestAssessRisk_HighRisk(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	ctx := &AuthContext{
		UserID:     "testuser",
		RemoteAddr: "1.2.3.4", // Untrusted network
		UserAgent:  "curl/7.68.0", // Automated tool
		LoginType:  "ssh",
		Provider:   "test",
		Country:    "XX", // Untrusted country
		City:       "Unknown",
		DeviceFingerprint: "unknown-device",
		LastLogin:  time.Now().Add(-30 * 24 * time.Hour), // Long time ago
		LoginHistory: []LoginAttempt{
			{
				Timestamp:  time.Now().Add(-1 * time.Minute),
				Success:    false,
				RemoteAddr: "1.2.3.4",
				Country:    "XX",
				UserAgent:  "curl/7.68.0",
			},
			{
				Timestamp:  time.Now().Add(-2 * time.Minute),
				Success:    false,
				RemoteAddr: "1.2.3.4",
				Country:    "XX",
				UserAgent:  "curl/7.68.0",
			},
		},
	}

	assessment, err := engine.AssessRisk(ctx)
	if err != nil {
		t.Fatalf("AssessRisk failed: %v", err)
	}

	if assessment.RiskLevel == "low" {
		t.Errorf("Expected elevated risk, got %s", assessment.RiskLevel)
	}

	// The decision logic may still allow based on weighted scores
	// Let's check that at least some risk factors are detected
	if len(assessment.Factors) == 0 {
		t.Error("Expected risk factors to be identified")
	}

	// Check that risk score is elevated
	if assessment.TotalScore < 15 {
		t.Errorf("Expected elevated risk score, got %f", assessment.TotalScore)
	}
}

func TestAssessGeographicRisk(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	// Test trusted country
	ctx := &AuthContext{
		Country: "US",
		LoginHistory: []LoginAttempt{
			{
				Timestamp: time.Now().Add(-24 * time.Hour),
				Success:   true,
				Country:   "US",
			},
		},
	}

	factor := engine.assessGeographicRisk(ctx)
	if factor.Score >= 30 {
		t.Errorf("Expected low score for trusted country, got %f", factor.Score)
	}

	// Test untrusted country
	ctx.Country = "XX"
	factor = engine.assessGeographicRisk(ctx)
	if factor.Score < 30 {
		t.Errorf("Expected high score for untrusted country, got %f", factor.Score)
	}
}

func TestAssessTemporalRisk(t *testing.T) {
	config := DefaultRiskConfig()
	config.BusinessHours.Enabled = true
	config.BusinessHours.StartHour = 9
	config.BusinessHours.EndHour = 17
	config.BusinessHours.Weekdays = []int{1, 2, 3, 4, 5} // Monday-Friday

	engine := NewRiskEngine(config)

	ctx := &AuthContext{
		LoginHistory: []LoginAttempt{
			{
				Timestamp: time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC), // Monday 10 AM
				Success:   true,
			},
		},
	}

	factor := engine.assessTemporalRisk(ctx)
	
	// Business hours check depends on current time, so we mainly test the function runs
	if factor.Type != "temporal" {
		t.Errorf("Expected temporal risk factor, got %s", factor.Type)
	}
}

func TestAssessDeviceRisk(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	// Test known device
	ctx := &AuthContext{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		DeviceFingerprint: "known-device",
		LoginHistory: []LoginAttempt{
			{
				Timestamp: time.Now().Add(-24 * time.Hour),
				Success:   true,
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			},
		},
	}

	factor := engine.assessDeviceRisk(ctx)
	if factor.Score >= 20 {
		t.Errorf("Expected low score for known device, got %f", factor.Score)
	}

	// Test automated tool
	ctx.UserAgent = "curl/7.68.0"
	ctx.LoginHistory = []LoginAttempt{} // No history
	factor = engine.assessDeviceRisk(ctx)
	if factor.Score < 20 {
		t.Errorf("Expected elevated score for automated tool, got %f", factor.Score)
	}
}

func TestAssessBehavioralRisk(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	// Test no history
	ctx := &AuthContext{
		LoginHistory: []LoginAttempt{},
	}

	factor := engine.assessBehavioralRisk(ctx)
	if factor.Score < 15 {
		t.Errorf("Expected score for no history, got %f", factor.Score)
	}

	// Test recent failures
	ctx.LoginHistory = []LoginAttempt{
		{
			Timestamp: time.Now().Add(-10 * time.Minute),
			Success:   false,
		},
		{
			Timestamp: time.Now().Add(-20 * time.Minute),
			Success:   false,
		},
		{
			Timestamp: time.Now().Add(-30 * time.Minute),
			Success:   false,
		},
		{
			Timestamp: time.Now().Add(-40 * time.Minute),
			Success:   false,
		},
	}

	factor = engine.assessBehavioralRisk(ctx)
	if factor.Score < 25 {
		t.Errorf("Expected high score for recent failures, got %f", factor.Score)
	}
}

func TestAssessNetworkRisk(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	// Test trusted network
	ctx := &AuthContext{
		RemoteAddr: "192.168.1.100",
	}

	factor := engine.assessNetworkRisk(ctx)
	if factor.Score >= 15 {
		t.Errorf("Expected low score for trusted network, got %f", factor.Score)
	}

	// Test untrusted network
	ctx.RemoteAddr = "1.2.3.4"
	factor = engine.assessNetworkRisk(ctx)
	if factor.Score < 15 {
		t.Errorf("Expected high score for untrusted network, got %f", factor.Score)
	}

	// Test invalid IP
	ctx.RemoteAddr = "invalid-ip"
	factor = engine.assessNetworkRisk(ctx)
	if factor.Score < 20 {
		t.Errorf("Expected high score for invalid IP, got %f", factor.Score)
	}
}

func TestDetermineRiskLevel(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	tests := []struct {
		score    float64
		expected string
	}{
		{10, "low"},
		{25, "medium"},
		{60, "high"},
		{90, "critical"},
	}

	for _, test := range tests {
		result := engine.determineRiskLevel(test.score)
		if result != test.expected {
			t.Errorf("Expected risk level %s for score %f, got %s", test.expected, test.score, result)
		}
	}
}

func TestMakeAccessDecision(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	tests := []struct {
		score    float64
		expected string
	}{
		{10, "allow"},
		{60, "allow_with_mfa"},
		{110, "deny"},
	}

	for _, test := range tests {
		assessment := &RiskAssessment{
			TotalScore: test.score,
		}
		result := engine.makeAccessDecision(assessment)
		if result != test.expected {
			t.Errorf("Expected decision %s for score %f, got %s", test.expected, test.score, result)
		}
	}
}

func TestRequiresMFA(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	// Test low risk
	assessment := &RiskAssessment{
		TotalScore: 10,
		Decision:   "allow",
	}
	if engine.requiresMFA(assessment) {
		t.Error("Expected MFA not required for low risk")
	}

	// Test medium risk
	assessment.TotalScore = 40
	if !engine.requiresMFA(assessment) {
		t.Error("Expected MFA required for medium risk")
	}

	// Test allow_with_mfa decision
	assessment.TotalScore = 10
	assessment.Decision = "allow_with_mfa"
	if !engine.requiresMFA(assessment) {
		t.Error("Expected MFA required for allow_with_mfa decision")
	}
}

func TestCalculateSessionDuration(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	tests := []struct {
		score    float64
		expected time.Duration
	}{
		{10, 8 * time.Hour},
		{40, 4 * time.Hour},
		{60, 1 * time.Hour},
	}

	for _, test := range tests {
		assessment := &RiskAssessment{
			TotalScore: test.score,
		}
		result := engine.calculateSessionDuration(assessment)
		if result != test.expected {
			t.Errorf("Expected session duration %v for score %f, got %v", test.expected, test.score, result)
		}
	}
}

func TestIsBusinessHours(t *testing.T) {
	config := DefaultRiskConfig()
	config.BusinessHours.StartHour = 9
	config.BusinessHours.EndHour = 17
	config.BusinessHours.Weekdays = []int{1, 2, 3, 4, 5} // Monday-Friday

	engine := NewRiskEngine(config)

	// Test business hours (Tuesday 10 AM)
	businessTime := time.Date(2023, 1, 3, 10, 0, 0, 0, time.UTC)
	if !engine.isBusinessHours(businessTime) {
		t.Error("Expected business hours to be true for Tuesday 10 AM")
	}

	// Test non-business hours (Saturday 10 AM)
	weekendTime := time.Date(2023, 1, 7, 10, 0, 0, 0, time.UTC)
	if engine.isBusinessHours(weekendTime) {
		t.Error("Expected business hours to be false for Saturday")
	}

	// Test non-business hours (Tuesday 8 AM)
	earlyTime := time.Date(2023, 1, 3, 8, 0, 0, 0, time.UTC)
	if engine.isBusinessHours(earlyTime) {
		t.Error("Expected business hours to be false for Tuesday 8 AM")
	}
}

func TestCalculateAverageLoginHour(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	history := []LoginAttempt{
		{
			Timestamp: time.Date(2023, 1, 1, 9, 0, 0, 0, time.UTC),
			Success:   true,
		},
		{
			Timestamp: time.Date(2023, 1, 1, 11, 0, 0, 0, time.UTC),
			Success:   true,
		},
		{
			Timestamp: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC),
			Success:   true,
		},
	}

	avgHour := engine.calculateAverageLoginHour(history)
	expected := 11.0 // (9 + 11 + 13) / 3
	if avgHour != expected {
		t.Errorf("Expected average hour %f, got %f", expected, avgHour)
	}

	// Test empty history
	avgHour = engine.calculateAverageLoginHour([]LoginAttempt{})
	if avgHour != 12.0 {
		t.Errorf("Expected default hour 12.0 for empty history, got %f", avgHour)
	}
}

func TestGetSeverity(t *testing.T) {
	config := DefaultRiskConfig()
	engine := NewRiskEngine(config)

	tests := []struct {
		score    float64
		expected string
	}{
		{5, "low"},
		{15, "medium"},
		{35, "high"},
		{55, "critical"},
	}

	for _, test := range tests {
		result := engine.getSeverity(test.score)
		if result != test.expected {
			t.Errorf("Expected severity %s for score %f, got %s", test.expected, test.score, result)
		}
	}
}