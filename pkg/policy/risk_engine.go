package policy

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// RiskEngine implements advanced risk-based access control
type RiskEngine struct {
	config *RiskConfig
}

// RiskConfig holds configuration for risk assessment
type RiskConfig struct {
	MaxRiskScore      float64            `yaml:"max_risk_score"`
	GeoRiskEnabled    bool               `yaml:"geo_risk_enabled"`
	TimeRiskEnabled   bool               `yaml:"time_risk_enabled"`
	DeviceRiskEnabled bool               `yaml:"device_risk_enabled"`
	BehaviorRiskEnabled bool             `yaml:"behavior_risk_enabled"`
	TrustedNetworks   []string           `yaml:"trusted_networks"`
	TrustedCountries  []string           `yaml:"trusted_countries"`
	BusinessHours     BusinessHours      `yaml:"business_hours"`
	RiskWeights       RiskWeights        `yaml:"risk_weights"`
}

// BusinessHours defines allowed business hours
type BusinessHours struct {
	Enabled   bool   `yaml:"enabled"`
	StartHour int    `yaml:"start_hour"`
	EndHour   int    `yaml:"end_hour"`
	Weekdays  []int  `yaml:"weekdays"` // 0=Sunday, 1=Monday, etc.
	Timezone  string `yaml:"timezone"`
}

// RiskWeights defines weights for different risk factors
type RiskWeights struct {
	Geographic float64 `yaml:"geographic"`
	Temporal   float64 `yaml:"temporal"`
	Device     float64 `yaml:"device"`
	Behavioral float64 `yaml:"behavioral"`
	Network    float64 `yaml:"network"`
}

// RiskAssessment represents a risk assessment result
type RiskAssessment struct {
	TotalScore       float64             `json:"total_score"`
	MaxScore         float64             `json:"max_score"`
	RiskLevel        string              `json:"risk_level"`
	Factors          []RiskFactor        `json:"factors"`
	Recommendations  []string            `json:"recommendations"`
	Decision         string              `json:"decision"`
	RequiredMFA      bool                `json:"required_mfa"`
	SessionDuration  time.Duration       `json:"session_duration"`
	AssessmentTime   time.Time           `json:"assessment_time"`
}

// RiskFactor represents an individual risk factor
type RiskFactor struct {
	Type        string  `json:"type"`
	Score       float64 `json:"score"`
	Weight      float64 `json:"weight"`
	WeightedScore float64 `json:"weighted_score"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
}

// AuthContext contains information needed for risk assessment
type AuthContext struct {
	UserID         string            `json:"user_id"`
	RemoteAddr     string            `json:"remote_addr"`
	UserAgent      string            `json:"user_agent"`
	LoginType      string            `json:"login_type"`
	Provider       string            `json:"provider"`
	Country        string            `json:"country"`
	City           string            `json:"city"`
	DeviceFingerprint string         `json:"device_fingerprint"`
	LastLogin      time.Time         `json:"last_login"`
	LoginHistory   []LoginAttempt    `json:"login_history"`
	Metadata       map[string]string `json:"metadata"`
}

// LoginAttempt represents a historical login attempt
type LoginAttempt struct {
	Timestamp  time.Time `json:"timestamp"`
	Success    bool      `json:"success"`
	RemoteAddr string    `json:"remote_addr"`
	Country    string    `json:"country"`
	UserAgent  string    `json:"user_agent"`
}

// NewRiskEngine creates a new risk assessment engine
func NewRiskEngine(config *RiskConfig) *RiskEngine {
	return &RiskEngine{
		config: config,
	}
}

// DefaultRiskConfig returns a default risk configuration
func DefaultRiskConfig() *RiskConfig {
	return &RiskConfig{
		MaxRiskScore:        100.0,
		GeoRiskEnabled:      true,
		TimeRiskEnabled:     true,
		DeviceRiskEnabled:   true,
		BehaviorRiskEnabled: true,
		TrustedNetworks:     []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		TrustedCountries:    []string{"US", "CA", "GB"},
		BusinessHours: BusinessHours{
			Enabled:   true,
			StartHour: 8,
			EndHour:   18,
			Weekdays:  []int{1, 2, 3, 4, 5}, // Monday-Friday
			Timezone:  "UTC",
		},
		RiskWeights: RiskWeights{
			Geographic: 0.3,
			Temporal:   0.2,
			Device:     0.2,
			Behavioral: 0.2,
			Network:    0.1,
		},
	}
}

// AssessRisk performs a comprehensive risk assessment
func (re *RiskEngine) AssessRisk(ctx *AuthContext) (*RiskAssessment, error) {
	log.Debug().
		Str("user_id", ctx.UserID).
		Str("remote_addr", ctx.RemoteAddr).
		Msg("Starting risk assessment")

	assessment := &RiskAssessment{
		MaxScore:       re.config.MaxRiskScore,
		Factors:        []RiskFactor{},
		Recommendations: []string{},
		AssessmentTime: time.Now(),
	}

	// Assess different risk factors
	if re.config.GeoRiskEnabled {
		factor := re.assessGeographicRisk(ctx)
		assessment.Factors = append(assessment.Factors, factor)
	}

	if re.config.TimeRiskEnabled {
		factor := re.assessTemporalRisk(ctx)
		assessment.Factors = append(assessment.Factors, factor)
	}

	if re.config.DeviceRiskEnabled {
		factor := re.assessDeviceRisk(ctx)
		assessment.Factors = append(assessment.Factors, factor)
	}

	if re.config.BehaviorRiskEnabled {
		factor := re.assessBehavioralRisk(ctx)
		assessment.Factors = append(assessment.Factors, factor)
	}

	// Always assess network risk
	factor := re.assessNetworkRisk(ctx)
	assessment.Factors = append(assessment.Factors, factor)

	// Calculate total risk score
	totalScore := 0.0
	for _, factor := range assessment.Factors {
		totalScore += factor.WeightedScore
	}
	assessment.TotalScore = totalScore

	// Determine risk level
	assessment.RiskLevel = re.determineRiskLevel(totalScore)

	// Make access decision
	assessment.Decision = re.makeAccessDecision(assessment)

	// Determine MFA requirement
	assessment.RequiredMFA = re.requiresMFA(assessment)

	// Set session duration based on risk
	assessment.SessionDuration = re.calculateSessionDuration(assessment)

	// Generate recommendations
	assessment.Recommendations = re.generateRecommendations(assessment)

	log.Info().
		Str("user_id", ctx.UserID).
		Float64("risk_score", totalScore).
		Str("risk_level", assessment.RiskLevel).
		Str("decision", assessment.Decision).
		Msg("Risk assessment completed")

	return assessment, nil
}

// assessGeographicRisk assesses risk based on geographic location
func (re *RiskEngine) assessGeographicRisk(ctx *AuthContext) RiskFactor {
	score := 0.0
	description := "Geographic location assessment"

	// Check if country is in trusted list
	if !contains(re.config.TrustedCountries, ctx.Country) {
		score += 30.0
		description = fmt.Sprintf("Login from untrusted country: %s", ctx.Country)
	}

	// Check for unusual location based on login history
	if len(ctx.LoginHistory) > 0 {
		recentCountries := make(map[string]int)
		for _, login := range ctx.LoginHistory {
			if login.Success && time.Since(login.Timestamp) < 30*24*time.Hour {
				recentCountries[login.Country]++
			}
		}

		if len(recentCountries) > 0 && recentCountries[ctx.Country] == 0 {
			score += 20.0
			description += " (new location)"
		}
	}

	weightedScore := score * re.config.RiskWeights.Geographic
	severity := re.getSeverity(score)

	return RiskFactor{
		Type:          "geographic",
		Score:         score,
		Weight:        re.config.RiskWeights.Geographic,
		WeightedScore: weightedScore,
		Description:   description,
		Severity:      severity,
	}
}

// assessTemporalRisk assesses risk based on time of access
func (re *RiskEngine) assessTemporalRisk(ctx *AuthContext) RiskFactor {
	score := 0.0
	description := "Time-based access assessment"

	now := time.Now()
	
	// Check business hours
	if re.config.BusinessHours.Enabled {
		if !re.isBusinessHours(now) {
			score += 25.0
			description = "Access outside business hours"
		}
	}

	// Check for unusual time patterns
	if len(ctx.LoginHistory) > 0 {
		avgHour := re.calculateAverageLoginHour(ctx.LoginHistory)
		currentHour := float64(now.Hour())
		
		timeDiff := math.Abs(currentHour - avgHour)
		if timeDiff > 6 { // More than 6 hours difference
			score += 15.0
			description += " (unusual time pattern)"
		}
	}

	weightedScore := score * re.config.RiskWeights.Temporal
	severity := re.getSeverity(score)

	return RiskFactor{
		Type:          "temporal",
		Score:         score,
		Weight:        re.config.RiskWeights.Temporal,
		WeightedScore: weightedScore,
		Description:   description,
		Severity:      severity,
	}
}

// assessDeviceRisk assesses risk based on device characteristics
func (re *RiskEngine) assessDeviceRisk(ctx *AuthContext) RiskFactor {
	score := 0.0
	description := "Device fingerprint assessment"

	// Check if device is known
	if ctx.DeviceFingerprint != "" {
		knownDevice := false
		for _, login := range ctx.LoginHistory {
			if login.Success && login.UserAgent == ctx.UserAgent {
				knownDevice = true
				break
			}
		}

		if !knownDevice {
			score += 20.0
			description = "New or unknown device"
		}
	} else {
		score += 10.0
		description = "No device fingerprint available"
	}

	// Analyze User-Agent string
	userAgent := strings.ToLower(ctx.UserAgent)
	if strings.Contains(userAgent, "bot") || strings.Contains(userAgent, "crawler") {
		score += 40.0
		description += " (automated tool detected)"
	}

	weightedScore := score * re.config.RiskWeights.Device
	severity := re.getSeverity(score)

	return RiskFactor{
		Type:          "device",
		Score:         score,
		Weight:        re.config.RiskWeights.Device,
		WeightedScore: weightedScore,
		Description:   description,
		Severity:      severity,
	}
}

// assessBehavioralRisk assesses risk based on behavioral patterns
func (re *RiskEngine) assessBehavioralRisk(ctx *AuthContext) RiskFactor {
	score := 0.0
	description := "Behavioral pattern assessment"

	if len(ctx.LoginHistory) == 0 {
		score += 15.0
		description = "No login history available"
	} else {
		// Check for rapid successive logins
		recentLogins := 0
		for _, login := range ctx.LoginHistory {
			if time.Since(login.Timestamp) < 5*time.Minute {
				recentLogins++
			}
		}

		if recentLogins > 5 {
			score += 30.0
			description = "Rapid successive login attempts"
		}

		// Check failure rate
		failures := 0
		for _, login := range ctx.LoginHistory {
			if !login.Success && time.Since(login.Timestamp) < 1*time.Hour {
				failures++
			}
		}

		if failures > 3 {
			score += 25.0
			description += " (recent failures detected)"
		}
	}

	weightedScore := score * re.config.RiskWeights.Behavioral
	severity := re.getSeverity(score)

	return RiskFactor{
		Type:          "behavioral",
		Score:         score,
		Weight:        re.config.RiskWeights.Behavioral,
		WeightedScore: weightedScore,
		Description:   description,
		Severity:      severity,
	}
}

// assessNetworkRisk assesses risk based on network characteristics
func (re *RiskEngine) assessNetworkRisk(ctx *AuthContext) RiskFactor {
	score := 0.0
	description := "Network-based risk assessment"

	ip := net.ParseIP(ctx.RemoteAddr)
	if ip == nil {
		score += 20.0
		description = "Invalid IP address"
	} else {
		// Check if IP is in trusted networks
		trusted := false
		for _, network := range re.config.TrustedNetworks {
			if _, cidr, err := net.ParseCIDR(network); err == nil {
				if cidr.Contains(ip) {
					trusted = true
					break
				}
			}
		}

		if !trusted {
			score += 15.0
			description = "Access from untrusted network"
		}

		// Check for private IP ranges (could indicate VPN/proxy)
		if ip.IsPrivate() {
			score += 5.0
			description += " (private IP)"
		}
	}

	weightedScore := score * re.config.RiskWeights.Network
	severity := re.getSeverity(score)

	return RiskFactor{
		Type:          "network",
		Score:         score,
		Weight:        re.config.RiskWeights.Network,
		WeightedScore: weightedScore,
		Description:   description,
		Severity:      severity,
	}
}

// Helper functions

func (re *RiskEngine) determineRiskLevel(score float64) string {
	if score < 20 {
		return "low"
	} else if score < 50 {
		return "medium"
	} else if score < 80 {
		return "high"
	} else {
		return "critical"
	}
}

func (re *RiskEngine) makeAccessDecision(assessment *RiskAssessment) string {
	if assessment.TotalScore >= re.config.MaxRiskScore {
		return "deny"
	} else if assessment.TotalScore >= 50 {
		return "allow_with_mfa"
	} else {
		return "allow"
	}
}

func (re *RiskEngine) requiresMFA(assessment *RiskAssessment) bool {
	return assessment.TotalScore >= 30 || assessment.Decision == "allow_with_mfa"
}

func (re *RiskEngine) calculateSessionDuration(assessment *RiskAssessment) time.Duration {
	baseDuration := 8 * time.Hour
	
	if assessment.TotalScore >= 50 {
		return 1 * time.Hour
	} else if assessment.TotalScore >= 30 {
		return 4 * time.Hour
	} else {
		return baseDuration
	}
}

func (re *RiskEngine) generateRecommendations(assessment *RiskAssessment) []string {
	var recommendations []string

	if assessment.TotalScore >= 50 {
		recommendations = append(recommendations, "Consider blocking access or requiring additional verification")
	}

	if assessment.RequiredMFA {
		recommendations = append(recommendations, "Require multi-factor authentication")
	}

	for _, factor := range assessment.Factors {
		if factor.Score >= 30 {
			recommendations = append(recommendations, fmt.Sprintf("High %s risk detected: %s", factor.Type, factor.Description))
		}
	}

	if assessment.SessionDuration < 4*time.Hour {
		recommendations = append(recommendations, "Use shortened session duration")
	}

	return recommendations
}

func (re *RiskEngine) isBusinessHours(t time.Time) bool {
	hour := t.Hour()
	weekday := int(t.Weekday())

	if hour < re.config.BusinessHours.StartHour || hour >= re.config.BusinessHours.EndHour {
		return false
	}

	return containsInt(re.config.BusinessHours.Weekdays, weekday)
}

func (re *RiskEngine) calculateAverageLoginHour(history []LoginAttempt) float64 {
	if len(history) == 0 {
		return 12.0 // Default to noon
	}

	totalHours := 0.0
	count := 0

	for _, login := range history {
		if login.Success {
			totalHours += float64(login.Timestamp.Hour())
			count++
		}
	}

	if count == 0 {
		return 12.0
	}

	return totalHours / float64(count)
}

func (re *RiskEngine) getSeverity(score float64) string {
	if score < 10 {
		return "low"
	} else if score < 30 {
		return "medium"
	} else if score < 50 {
		return "high"
	} else {
		return "critical"
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}