package auth

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// PolicyEngine evaluates authentication policies
type PolicyEngine struct {
	config *config.Config
}

// PolicyResult represents the result of policy evaluation
type PolicyResult struct {
	Allowed       bool
	Reason        string
	RequiredMFA   bool
	RequiredGroups []string
	MaxDuration   time.Duration
	RiskScore     int
	RiskFactors   []string
	Metadata      map[string]interface{}
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(cfg *config.Config) (*PolicyEngine, error) {
	return &PolicyEngine{
		config: cfg,
	}, nil
}

// EvaluateRequest evaluates an authentication request against policies
func (pe *PolicyEngine) EvaluateRequest(req *AuthRequest) (*PolicyResult, error) {
	if req == nil {
		return nil, fmt.Errorf("authentication request cannot be nil")
	}
	
	log.Debug().
		Str("user_id", req.UserID).
		Str("source_ip", req.SourceIP).
		Str("target_host", req.TargetHost).
		Str("login_type", req.LoginType).
		Msg("Evaluating authentication request")

	result := &PolicyResult{
		Allowed:     true,
		RiskScore:   0,
		RiskFactors: []string{},
		Metadata:    make(map[string]interface{}),
	}

	// Apply global policies
	if err := pe.applyGlobalPolicies(req, result); err != nil {
		return nil, fmt.Errorf("failed to apply global policies: %w", err)
	}

	// Apply network policies
	if err := pe.applyNetworkPolicies(req, result); err != nil {
		return nil, fmt.Errorf("failed to apply network policies: %w", err)
	}

	// Apply time-based policies
	if err := pe.applyTimeBasedPolicies(req, result); err != nil {
		return nil, fmt.Errorf("failed to apply time-based policies: %w", err)
	}

	// Apply risk-based policies
	if err := pe.applyRiskPolicies(req, result); err != nil {
		return nil, fmt.Errorf("failed to apply risk-based policies: %w", err)
	}

	// Apply resource-specific policies
	if err := pe.applyResourcePolicies(req, result); err != nil {
		return nil, fmt.Errorf("failed to apply resource policies: %w", err)
	}

	log.Debug().
		Bool("allowed", result.Allowed).
		Str("reason", result.Reason).
		Int("risk_score", result.RiskScore).
		Strs("risk_factors", result.RiskFactors).
		Msg("Policy evaluation completed")

	return result, nil
}

// applyGlobalPolicies applies global authentication policies
func (pe *PolicyEngine) applyGlobalPolicies(req *AuthRequest, result *PolicyResult) error {
	// Check required groups
	if len(pe.config.Authentication.RequireGroups) > 0 {
		result.RequiredGroups = pe.config.Authentication.RequireGroups
	}

	// Check max concurrent sessions
	if pe.config.Authentication.MaxConcurrentSessions > 0 {
		// This would check against active sessions
		// For now, we'll just log
		log.Debug().
			Int("max_sessions", pe.config.Authentication.MaxConcurrentSessions).
			Msg("Checking concurrent session limit")
	}

	return nil
}

// applyNetworkPolicies applies network-related policies
func (pe *PolicyEngine) applyNetworkPolicies(req *AuthRequest, result *PolicyResult) error {
	netReq := pe.config.Authentication.NetworkRequirements

	// Check if Tailscale is required
	if netReq.RequireTailscale {
		if !pe.isTailscaleIP(req.SourceIP) {
			result.Allowed = false
			result.Reason = "Access requires Tailscale network connection"
			return nil
		}
	}

	// Check private network requirement
	if netReq.RequirePrivateNetwork {
		if !pe.isPrivateIP(req.SourceIP) {
			result.Allowed = false
			result.Reason = "Access requires private network connection"
			return nil
		}
	}

	return nil
}

// applyTimeBasedPolicies applies time-based access policies
func (pe *PolicyEngine) applyTimeBasedPolicies(req *AuthRequest, result *PolicyResult) error {
	now := time.Now()

	// Check time restrictions
	for _, restriction := range pe.config.Authentication.TimeBasedPolicies.TimeRestrictions {
		if pe.matchesTimeRestriction(req, restriction, now) {
			if !pe.isWithinAllowedHours(restriction.AllowedHours, now, restriction.Timezone) {
				result.Allowed = false
				result.Reason = fmt.Sprintf("Access not allowed at this time: %s", restriction.AllowedHours)
				return nil
			}
		}
	}

	// Check geographic restrictions
	for _, restriction := range pe.config.Authentication.TimeBasedPolicies.GeoRestrictions {
		if pe.matchesGeoRestriction(req, restriction) {
			country := pe.getCountryFromIP(req.SourceIP)
			
			// Check blocked countries
			for _, blocked := range restriction.BlockedCountries {
				if country == blocked {
					result.Allowed = false
					result.Reason = fmt.Sprintf("Access blocked from country: %s", country)
					return nil
				}
			}
			
			// Check allowed countries
			if len(restriction.AllowedCountries) > 0 {
				allowed := false
				for _, allowedCountry := range restriction.AllowedCountries {
					if country == allowedCountry {
						allowed = true
						break
					}
				}
				if !allowed {
					result.Allowed = false
					result.Reason = fmt.Sprintf("Access not allowed from country: %s", country)
					return nil
				}
			}
		}
	}

	return nil
}

// applyRiskPolicies applies risk-based policies
func (pe *PolicyEngine) applyRiskPolicies(req *AuthRequest, result *PolicyResult) error {
	// Calculate risk score
	riskScore := pe.calculateRiskScore(req, result)
	result.RiskScore = riskScore

	// Apply risk policies
	for _, policy := range pe.config.Authentication.RiskPolicies {
		if pe.evaluateRiskCondition(policy.Condition, req, result) {
			switch policy.Action {
			case "DENY":
				result.Allowed = false
				result.Reason = policy.Recommendation
				return nil
			case "REQUIRE_ADDITIONAL_MFA":
				result.RequiredMFA = true
			case "REQUIRE_APPROVAL":
				result.Metadata["requires_approval"] = true
			}
		}
	}

	return nil
}

// applyResourcePolicies applies resource-specific policies
func (pe *PolicyEngine) applyResourcePolicies(req *AuthRequest, result *PolicyResult) error {
	// Find matching policy for target resource
	for policyName, policy := range pe.config.Authentication.Policies {
		if pe.matchesResourcePolicy(req.TargetHost, policyName) {
			// Apply policy requirements
			if len(policy.RequireGroups) > 0 {
				result.RequiredGroups = append(result.RequiredGroups, policy.RequireGroups...)
			}

			if policy.MaxSessionDuration > 0 {
				if result.MaxDuration == 0 || policy.MaxSessionDuration < result.MaxDuration {
					result.MaxDuration = policy.MaxSessionDuration
				}
			}

			if policy.RequireDeviceTrust {
				result.Metadata["require_device_trust"] = true
			}

			if policy.RequireAdditionalMFA {
				result.RequiredMFA = true
			}

			// Check IP whitelist
			if len(policy.IPWhitelist) > 0 {
				allowed := false
				for _, allowedIP := range policy.IPWhitelist {
					if pe.matchesIPPattern(req.SourceIP, allowedIP) {
						allowed = true
						break
					}
				}
				if !allowed {
					result.Allowed = false
					result.Reason = "Source IP not in whitelist"
					return nil
				}
			}

			break
		}
	}

	return nil
}

// Helper methods

func (pe *PolicyEngine) isTailscaleIP(ip string) bool {
	// Check if IP is in Tailscale range (100.64.0.0/10)
	tailscaleNet := &net.IPNet{
		IP:   net.ParseIP("100.64.0.0"),
		Mask: net.CIDRMask(10, 32),
	}
	
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && tailscaleNet.Contains(parsedIP)
}

func (pe *PolicyEngine) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func (pe *PolicyEngine) matchesTimeRestriction(req *AuthRequest, restriction config.TimeRestriction, now time.Time) bool {
	// Check if any providers match
	for _, provider := range restriction.Providers {
		if provider == "all" || strings.Contains(req.UserID, provider) {
			return true
		}
	}
	return false
}

func (pe *PolicyEngine) matchesGeoRestriction(req *AuthRequest, restriction config.GeoRestriction) bool {
	// Check if any providers match
	for _, provider := range restriction.Providers {
		if provider == "all" || strings.Contains(req.UserID, provider) {
			return true
		}
	}
	return false
}

func (pe *PolicyEngine) isWithinAllowedHours(allowedHours string, now time.Time, timezone string) bool {
	if allowedHours == "" {
		return true
	}

	// Parse timezone
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		log.Warn().Err(err).Str("timezone", timezone).Msg("Failed to load timezone")
		loc = time.UTC
	}

	// Convert to specified timezone
	localTime := now.In(loc)

	// Parse allowed hours (e.g., "09:00-17:00")
	parts := strings.Split(allowedHours, "-")
	if len(parts) != 2 {
		return true
	}

	startTime, err := time.ParseInLocation("15:04", parts[0], loc)
	if err != nil {
		return true
	}

	endTime, err := time.ParseInLocation("15:04", parts[1], loc)
	if err != nil {
		return true
	}

	// Adjust for current date
	startTime = time.Date(localTime.Year(), localTime.Month(), localTime.Day(),
		startTime.Hour(), startTime.Minute(), 0, 0, loc)
	endTime = time.Date(localTime.Year(), localTime.Month(), localTime.Day(),
		endTime.Hour(), endTime.Minute(), 0, 0, loc)

	return localTime.After(startTime) && localTime.Before(endTime)
}

func (pe *PolicyEngine) getCountryFromIP(ip string) string {
	// This would use a GeoIP database to determine country
	// For now, return a placeholder
	return "US"
}

func (pe *PolicyEngine) calculateRiskScore(req *AuthRequest, result *PolicyResult) int {
	score := 0

	// Time-based risk
	now := time.Now()
	if pe.isAfterHours(now) {
		score += 20
		result.RiskFactors = append(result.RiskFactors, "After-hours access")
	}

	// Location-based risk
	if pe.isUnusualLocation(req.UserID, req.SourceIP) {
		score += 30
		result.RiskFactors = append(result.RiskFactors, "Unusual location")
	}

	// Device-based risk
	if req.DeviceID == "" {
		score += 15
		result.RiskFactors = append(result.RiskFactors, "Unknown device")
	}

	// Network-based risk
	if !pe.isPrivateIP(req.SourceIP) {
		score += 25
		result.RiskFactors = append(result.RiskFactors, "Public network access")
	}

	return score
}

func (pe *PolicyEngine) evaluateRiskCondition(condition string, req *AuthRequest, result *PolicyResult) bool {
	// Simple condition evaluation
	// In a real implementation, this would be more sophisticated
	switch condition {
	case "risk_score >= 70":
		return result.RiskScore >= 70
	case "unusual_location AND after_hours":
		return pe.isUnusualLocation(req.UserID, req.SourceIP) && pe.isAfterHours(time.Now())
	case "untrusted_network":
		return !pe.isPrivateIP(req.SourceIP)
	default:
		return false
	}
}

func (pe *PolicyEngine) matchesResourcePolicy(targetHost, policyName string) bool {
	// Simple pattern matching
	// In a real implementation, this would support more complex patterns
	switch policyName {
	case "production":
		return strings.Contains(targetHost, "prod")
	case "staging":
		return strings.Contains(targetHost, "staging") || strings.Contains(targetHost, "stage")
	case "development":
		return strings.Contains(targetHost, "dev")
	default:
		return false
	}
}

func (pe *PolicyEngine) matchesIPPattern(ip, pattern string) bool {
	// Check if IP matches pattern (could be CIDR or exact match)
	if strings.Contains(pattern, "/") {
		// CIDR pattern
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		parsedIP := net.ParseIP(ip)
		return parsedIP != nil && network.Contains(parsedIP)
	}
	
	// Exact match
	return ip == pattern
}

func (pe *PolicyEngine) isAfterHours(now time.Time) bool {
	// Consider 6 PM to 6 AM as after hours
	hour := now.Hour()
	return hour >= 18 || hour < 6
}

func (pe *PolicyEngine) isUnusualLocation(userID, sourceIP string) bool {
	// This would check against historical location data
	// For now, return false
	return false
}