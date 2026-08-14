package auth

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	oidcmetrics "github.com/scttfrdmn/oidc-pam/pkg/metrics"
)

// PolicyEngine evaluates authentication policies
type PolicyEngine struct {
	config          *config.Config
	geoipDB         *geoip2.Reader
	locationHistory *LocationHistory
	metrics         *oidcmetrics.Metrics // nil when metrics are disabled

	// resourceHost is the host a per-resource policy is matched against: this
	// machine, the resource being logged into. It is deliberately not taken from
	// the request — see applyResourcePolicies (#158).
	resourceHost string
}

// SetMetrics attaches a Metrics instance to the policy engine.
func (pe *PolicyEngine) SetMetrics(m *oidcmetrics.Metrics) {
	pe.metrics = m
}

// PolicyResult represents the result of policy evaluation
type PolicyResult struct {
	Allowed        bool
	Reason         string
	RequiredMFA    bool
	RequiredGroups []string
	MaxDuration    time.Duration
	RiskScore      int
	RiskFactors    []string
	Metadata       map[string]interface{}
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(cfg *config.Config) (*PolicyEngine, error) {
	pe := &PolicyEngine{config: cfg}

	if cfg != nil && cfg.Authentication.GeoIPDatabasePath != "" {
		db, err := geoip2.Open(cfg.Authentication.GeoIPDatabasePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open GeoIP database %q: %w", cfg.Authentication.GeoIPDatabasePath, err)
		}
		pe.geoipDB = db
		log.Info().Str("path", cfg.Authentication.GeoIPDatabasePath).Msg("GeoIP database loaded")
	}

	if cfg != nil {
		pe.locationHistory = NewLocationHistory(cfg.Authentication.LocationHistory)
	} else {
		pe.locationHistory = NewLocationHistory(config.LocationHistoryConfig{})
	}

	// Resolve this host once. A per-resource policy names the resource it governs,
	// and the resource is this machine.
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		// Not fatal, but say so loudly: with no hostname, no per-resource policy can
		// match, and a policy that does not match enforces nothing — including its
		// require_groups.
		log.Warn().
			Err(err).
			Msg("Could not determine this host's name; per-resource policies cannot match and will not be enforced")
	}
	pe.resourceHost = hostname
	pe.warnAboutInertPolicies()

	return pe, nil
}

// DefaultPolicyName is the policy that governs every host. A policy under this
// name is always in effect; any other name is matched against this host's name.
//
// This exists because the name is the only selector a policy has, and the
// configuration every doc hands operators (QUICK-START.md, DEPLOYMENT.md) is
// `policies.default.require_groups` — a name intended as "all hosts", not as a
// hostname. Without a catch-all the documented configuration would match no host
// and enforce nothing.
const DefaultPolicyName = "default"

// warnAboutInertPolicies logs any configured policy that cannot match this host.
//
// A policy's name is its only selector, so a policy named for an environment
// ("production", "staging") matches only a host actually named that. Such a
// policy is silently inert — including its require_groups — which is how #158
// went unnoticed. Saying so at startup makes it visible instead.
func (pe *PolicyEngine) warnAboutInertPolicies() {
	if pe.config == nil {
		return
	}

	var inert []string
	for name := range pe.config.Authentication.Policies {
		if !pe.matchesResourcePolicy(pe.resourceHost, name) {
			inert = append(inert, name)
		}
	}
	if len(inert) == 0 {
		return
	}
	sort.Strings(inert)

	log.Warn().
		Strs("inert_policies", inert).
		Str("this_host", pe.resourceHost).
		Msgf("These authentication.policies entries do not apply to this host and will not be enforced. "+
			"A policy name must be %q (all hosts) or match this host's name; rename them or move their "+
			"require_groups to authentication.require_groups", DefaultPolicyName)
}

// RecordLocation records a successful login from sourceIP for userID so that
// future logins from the same /24 subnet or country are not flagged as unusual.
// Call this after authentication succeeds.
func (pe *PolicyEngine) RecordLocation(userID, sourceIP string) {
	if pe.locationHistory == nil {
		return
	}
	country := pe.getCountryFromIP(sourceIP)
	pe.locationHistory.RecordLocation(userID, sourceIP, country)
}

// Close releases resources held by the policy engine (e.g. the GeoIP database).
func (pe *PolicyEngine) Close() {
	if pe.geoipDB != nil {
		_ = pe.geoipDB.Close()
		pe.geoipDB = nil
	}
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

	if pe.metrics != nil {
		pe.metrics.RecordPolicyEval(result.Allowed, result.RiskScore)
	}

	return result, nil
}

// applyGlobalPolicies applies global authentication policies
func (pe *PolicyEngine) applyGlobalPolicies(req *AuthRequest, result *PolicyResult) error {
	// Check required groups
	if len(pe.config.Authentication.RequireGroups) > 0 {
		result.RequiredGroups = pe.config.Authentication.RequireGroups
	}

	// Note: MaxConcurrentSessions is enforced in Broker.Authenticate() which
	// has access to the session map. The policy engine does not own sessions.

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

// applyResourcePolicies applies resource-specific policies.
//
// (#158) Policies are matched against pe.resourceHost — this machine — and not
// against req.TargetHost. Despite its name, TargetHost is populated from PAM's
// PAM_RHOST by both clients (cmd/pam-module/cgo_bridge_linux.c get_user_info,
// pkg/pam/pam.go), which is the address of the host the user is connecting *from*.
// Matching policy names against that meant a policy named "production" only ever
// matched a client literally named "production", so the whole policies: block —
// its require_groups, its ip_whitelist, its max_session_duration — never fired.
//
// (#158) Every matching policy is applied, not just the first one found. The old
// loop ranged over a map and broke on the first match, so when more than one
// policy matched — which is now normal, since DefaultPolicyName matches every
// host — which policy took effect varied between runs of the same binary on the
// same host. Applying all of them is both deterministic and the safer reading:
// require_groups unions and max_session_duration takes the minimum, so more
// matching policies can only ever restrict access further.
func (pe *PolicyEngine) applyResourcePolicies(req *AuthRequest, result *PolicyResult) error {
	// Sorted so that the denial reported for an ip_whitelist miss names the same
	// policy every time.
	names := make([]string, 0, len(pe.config.Authentication.Policies))
	for name := range pe.config.Authentication.Policies {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, policyName := range names {
		policy := pe.config.Authentication.Policies[policyName]
		if pe.matchesResourcePolicy(pe.resourceHost, policyName) {
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
	// "all" applies to every user. Provider-scoped matching requires a ProviderName
	// field on AuthRequest (TODO: add when provider selection moves earlier in the flow).
	for _, provider := range restriction.Providers {
		if provider == "all" {
			return true
		}
	}
	return false
}

func (pe *PolicyEngine) matchesGeoRestriction(req *AuthRequest, restriction config.GeoRestriction) bool {
	// "all" applies to every user. Provider-scoped matching requires a ProviderName
	// field on AuthRequest (TODO: add when provider selection moves earlier in the flow).
	for _, provider := range restriction.Providers {
		if provider == "all" {
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

// getCountryFromIP returns the ISO 3166-1 alpha-2 country code for the given IP
// address. Returns an empty string if the country cannot be determined (private
// address, loopback, or no GeoIP database configured).
func (pe *PolicyEngine) getCountryFromIP(ipStr string) string {
	if pe.geoipDB == nil {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Debug().Str("ip", ipStr).Msg("GeoIP: invalid IP address")
		return ""
	}

	// Private and loopback addresses have no meaningful country.
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return ""
	}

	record, err := pe.geoipDB.Country(ip)
	if err != nil {
		log.Debug().Err(err).Str("ip", ipStr).Msg("GeoIP lookup failed")
		return ""
	}

	return record.Country.IsoCode
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
		// L-7: an unrecognized condition silently evaluates to "does not fire",
		// which means a misconfigured DENY policy would never apply. Log loudly so
		// the misconfiguration is visible rather than failing open silently.
		log.Warn().
			Str("condition", condition).
			Msg("Unknown risk policy condition; it will not match. Check policy configuration")
		return false
	}
}

func (pe *PolicyEngine) matchesResourcePolicy(targetHost, policyName string) bool {
	// DefaultPolicyName governs every host, including one whose name could not be
	// determined. See the constant's doc comment.
	if policyName == DefaultPolicyName {
		return true
	}

	// Match exact hostname or hosts in a subdomain of policyName.
	// e.g. policy "production" matches "production" and "api.production.example.com"
	// but NOT "not-production" or "production-test".
	return targetHost == policyName ||
		strings.HasPrefix(targetHost, policyName+".") ||
		strings.Contains(targetHost, "."+policyName+".")
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
	if pe.locationHistory == nil {
		return false
	}
	country := pe.getCountryFromIP(sourceIP)
	return pe.locationHistory.IsUnusual(userID, sourceIP, country)
}
