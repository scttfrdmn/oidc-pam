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

	// riskPolicies are the configured risk policies with their conditions already
	// parsed. Parsing at startup rather than per login is what makes a
	// misconfigured condition a startup failure instead of a policy that silently
	// never matches (#213).
	riskPolicies []parsedRiskPolicy

	// timeRestrictions and geoRestrictions are the configured restrictions with
	// their windows parsed and their provider scopes resolved, for the same reason.
	timeRestrictions []parsedTimeRestriction
	geoRestrictions  []parsedGeoRestriction
}

// parsedRiskPolicy is a risk policy the engine has fully understood.
type parsedRiskPolicy struct {
	condition      riskCondition
	action         string
	recommendation string
}

// parsedTimeRestriction is a time restriction with its window parsed and its
// timezone resolved.
type parsedTimeRestriction struct {
	providers []string
	window    hourWindow
	location  *time.Location
	raw       string
}

// parsedGeoRestriction is a geographic restriction with its provider scope kept
// alongside its country lists.
type parsedGeoRestriction struct {
	providers        []string
	allowedCountries []string
	blockedCountries []string
}

// SetMetrics attaches a Metrics instance to the policy engine.
func (pe *PolicyEngine) SetMetrics(m *oidcmetrics.Metrics) {
	pe.metrics = m
}

// PolicyResult represents the result of policy evaluation
type PolicyResult struct {
	Allowed bool
	Reason  string
	// (#212) There is no RequiredMFA field. It had no reader, and the two settings
	// that wrote it — a policy's require_additional_mfa and a risk policy's
	// REQUIRE_ADDITIONAL_MFA action — are now refused at startup rather than
	// silently doing nothing. Reinstate it together with the code that acts on it.
	RequiredGroups []string
	MaxDuration    time.Duration
	RiskScore      int
	RiskFactors    []string
	Metadata       map[string]interface{}
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(cfg *config.Config) (*PolicyEngine, error) {
	pe := &PolicyEngine{config: cfg}

	// (#212) Before anything else: refuse a configuration whose access controls
	// this broker cannot enforce. Every check below is only worth running if the
	// operator's stated policy and the code's behaviour are the same thing.
	if err := validatePolicySupport(cfg); err != nil {
		return nil, err
	}
	if err := pe.compilePolicies(); err != nil {
		// Unreachable if validatePolicySupport is complete; returned rather than
		// ignored so that a gap between the two is a startup failure and not a
		// policy that silently never matches.
		return nil, err
	}

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

// EvaluateRequest evaluates an authentication request against policies.
//
// providerName is the provider that will serve this login, chosen by the broker
// before evaluation. It is a parameter rather than a field on AuthRequest because
// AuthRequest is built from what the client sent: a provider-scoped restriction
// that a client could opt out of by naming a different provider would be no
// restriction at all (#213). An empty providerName scopes out every restriction
// that names a provider, and leaves those scoped "all" in force.
func (pe *PolicyEngine) EvaluateRequest(req *AuthRequest, providerName string) (*PolicyResult, error) {
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
	if err := pe.applyTimeBasedPolicies(req, providerName, result); err != nil {
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

// MetadataSourceIPUnknown marks a result the network requirements let through
// only because the operator chose unknown_source_ip: allow. The broker audits
// it: a waived requirement is a security-relevant event, not a detail.
const MetadataSourceIPUnknown = "source_ip_unknown"

// MetadataRequireDeviceTrust marks a result whose matching policies required a
// trusted device. The broker carries it onto the session and enforces it once the
// identity is known — policy is evaluated before the device flow starts, so at
// evaluation time there is no amr claim to judge the device by (#212).
const MetadataRequireDeviceTrust = "require_device_trust"

// applyNetworkPolicies applies network-related policies
func (pe *PolicyEngine) applyNetworkPolicies(req *AuthRequest, result *PolicyResult) error {
	netReq := pe.config.Authentication.NetworkRequirements

	if !netReq.RequireTailscale && !netReq.RequirePrivateNetwork {
		return nil
	}

	// (#169) An absent source_ip means the broker does not know where this login
	// came from — not that it came from somewhere bad. Both checks below ask
	// net.ParseIP a question about a string, and both answer "no" for "", so an
	// unknown origin used to be reported as a public one and every login on the
	// host was refused. What happens instead is the operator's decision, made in
	// config and validated at startup (validateNetworkRequirements).
	if req.SourceIP == "" {
		if netReq.UnknownSourceIP == config.UnknownSourceIPAllow {
			result.RiskFactors = append(result.RiskFactors, "Network requirement waived: origin unknown")
			result.Metadata[MetadataSourceIPUnknown] = true
			log.Warn().
				Str("user_id", req.UserID).
				Str("login_type", req.LoginType).
				Msg("Login reported no source_ip; network requirements waived by unknown_source_ip: allow")
			return nil
		}
		result.Allowed = false
		result.Reason = "Access requires a known network origin; this login reported no source IP"
		return nil
	}

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

// applyTimeBasedPolicies applies the configured time and geographic restrictions
// that govern a login served by providerName.
func (pe *PolicyEngine) applyTimeBasedPolicies(req *AuthRequest, providerName string, result *PolicyResult) error {
	now := time.Now()

	for _, restriction := range pe.timeRestrictions {
		if !restrictionApplies(restriction.providers, providerName) {
			continue
		}
		if !restriction.window.contains(now.In(restriction.location)) {
			result.Allowed = false
			result.Reason = fmt.Sprintf("Access not allowed at this time: %s", restriction.raw)
			return nil
		}
	}

	for _, restriction := range pe.geoRestrictions {
		if !restrictionApplies(restriction.providers, providerName) {
			continue
		}
		country := pe.getCountryFromIP(req.SourceIP)

		for _, blocked := range restriction.blockedCountries {
			if country == blocked {
				result.Allowed = false
				result.Reason = fmt.Sprintf("Access blocked from country: %s", country)
				return nil
			}
		}

		if len(restriction.allowedCountries) > 0 {
			allowed := false
			for _, allowedCountry := range restriction.allowedCountries {
				if country == allowedCountry {
					allowed = true
					break
				}
			}
			if !allowed {
				// The reason names what the broker concluded rather than only what it
				// wanted, because "" here means the login could not be placed at all —
				// a private or loopback source address, or an address the GeoIP
				// database does not cover — and that is a different conversation with
				// the operator than "this login came from a country you excluded".
				if country == "" {
					result.Allowed = false
					result.Reason = fmt.Sprintf("Access is restricted to %s and this login's country "+
						"could not be determined from %q", strings.Join(restriction.allowedCountries, ", "),
						req.SourceIP)
					return nil
				}
				result.Allowed = false
				result.Reason = fmt.Sprintf("Access not allowed from country: %s", country)
				return nil
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

	// Apply risk policies. Conditions and actions were parsed and checked at
	// startup (#213), so there is no unrecognized case to skip over here.
	now := time.Now()
	for _, policy := range pe.riskPolicies {
		if !policy.condition.holds(pe, req, result, now) {
			continue
		}
		switch policy.action {
		case "DENY":
			result.Allowed = false
			// The condition is always named, even when the operator wrote a
			// recommendation: the recommendation says what the user should do, and
			// the audit trail has to say which rule fired (#218). A blank
			// recommendation used to make the reason blank, which is
			// indistinguishable from a bug.
			result.Reason = fmt.Sprintf("denied by risk policy %q (risk score %d)",
				policy.condition.raw, result.RiskScore)
			if policy.recommendation != "" {
				result.Reason += ": " + policy.recommendation
			}
			return nil
		case "LOG":
			log.Info().
				Str("user_id", req.UserID).
				Str("condition", policy.condition.raw).
				Int("risk_score", result.RiskScore).
				Strs("risk_factors", result.RiskFactors).
				Str("recommendation", policy.recommendation).
				Msg("Risk policy matched")
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
				result.Metadata[MetadataRequireDeviceTrust] = true
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
					// Named, because the reason is what the audit trail carries and
					// what an operator debugging a lockout reads (#218). "Source IP
					// not in whitelist" does not say which of several matching
					// policies refused, nor what address was compared, so it left
					// the operator to guess both.
					result.Reason = fmt.Sprintf("source IP %q is not in the ip_whitelist of policy %q",
						req.SourceIP, policyName)
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

	// Network-based risk. (#169) An unknown origin scores the same as a public one
	// — it is not evidence of safety — but it is named for what it is, because the
	// risk factors are what an operator reads out of the audit trail to work out
	// why a login scored what it did.
	switch {
	case req.SourceIP == "":
		score += 25
		result.RiskFactors = append(result.RiskFactors, "Unknown network origin")
	case !pe.isPrivateIP(req.SourceIP):
		score += 25
		result.RiskFactors = append(result.RiskFactors, "Public network access")
	}

	return score
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
