package auth

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// This file decides what the broker will admit it can enforce.
//
// (#212) Ten settings under authentication.policies were parsed, documented, and
// shipped in the example configurations, and did nothing at all. Eight had no
// reader anywhere in the product. The other two — require_additional_mfa and
// require_approval_for — reached a PolicyResult field that nothing read, which is
// the same outcome by a longer route. So did max_session_duration, whose
// per-policy minimum was computed on every login and then discarded, and
// require_device_trust, which set a metadata key no code looked at.
//
// An operator who writes `require_additional_mfa: true` has stated a requirement.
// A broker that starts anyway is answering "yes, that is in force" to a question
// it cannot answer, and the answer is wrong for as long as the deployment lives.
// The two that can be enforced now are; the rest make startup fail with the key
// named. Failing at startup is loud, is in the journal, happens on upgrade rather
// than during an incident, and cannot be mistaken for protection.
//
// The alternative — a warning — is what the previous release used for policies
// that could not match a host (#158), and it is the wrong instrument here.
// A warning leaves a running broker whose configuration claims a control it does
// not have.

// compilePolicies turns the configured risk policies and restrictions into the
// forms the engine evaluates, once, at startup.
//
// (#213) The parsing used to happen per login, and every parse failure took the
// permissive branch: an unrecognized risk condition never matched, an unparseable
// allowed_hours permitted every hour, an unloadable timezone became UTC. Doing it
// here means those are startup errors, and the evaluation path has no failure mode
// left to fall open through. validatePolicySupport reports all of them together
// with their configuration paths, so this returning an error at all means the two
// have drifted.
func (pe *PolicyEngine) compilePolicies() error {
	if pe.config == nil {
		return nil
	}

	for i, rp := range pe.config.Authentication.RiskPolicies {
		condition, err := parseRiskCondition(rp.Condition)
		if err != nil {
			return fmt.Errorf("authentication.risk_policies[%d].condition: %w", i, err)
		}
		if !riskPolicyActions[rp.Action] {
			return fmt.Errorf("authentication.risk_policies[%d].action: %q is not an action this broker "+
				"performs", i, rp.Action)
		}
		pe.riskPolicies = append(pe.riskPolicies, parsedRiskPolicy{
			condition:      condition,
			action:         rp.Action,
			recommendation: rp.Recommendation,
		})
	}

	for i, r := range pe.config.Authentication.TimeBasedPolicies.TimeRestrictions {
		window, err := parseAllowedHours(r.AllowedHours)
		if err != nil {
			return fmt.Errorf("authentication.time_based_policies.time_restrictions[%d].allowed_hours: %w", i, err)
		}
		location := time.UTC
		if r.Timezone != "" {
			loaded, err := time.LoadLocation(r.Timezone)
			if err != nil {
				return fmt.Errorf("authentication.time_based_policies.time_restrictions[%d].timezone: %w", i, err)
			}
			location = loaded
		}
		pe.timeRestrictions = append(pe.timeRestrictions, parsedTimeRestriction{
			providers: r.Providers,
			window:    window,
			location:  location,
			raw:       r.AllowedHours,
		})
	}

	for _, r := range pe.config.Authentication.TimeBasedPolicies.GeoRestrictions {
		pe.geoRestrictions = append(pe.geoRestrictions, parsedGeoRestriction{
			providers:        r.Providers,
			allowedCountries: r.AllowedCountries,
			blockedCountries: r.BlockedCountries,
		})
	}

	return nil
}

// restrictionApplies reports whether a restriction scoped to these providers
// governs a login being served by providerName.
//
// (#213) A restriction used to apply only if its provider list contained the
// literal "all"; a restriction naming a provider matched nothing, so its
// allowed_hours and its country lists were skipped and the login was allowed. The
// provider name is now known before policy is evaluated, so scoping works and
// "all" is one case of it rather than the only one.
//
// An empty provider list matches nothing, as before — but it can no longer be
// configured, because validatePolicySupport refuses it.
func restrictionApplies(providers []string, providerName string) bool {
	for _, p := range providers {
		if p == "all" {
			return true
		}
		if providerName != "" && strings.EqualFold(p, providerName) {
			return true
		}
	}
	return false
}

// unsupportedPolicySetting names one configured setting the broker cannot
// enforce, and says what to do about it.
type unsupportedPolicySetting struct {
	// key is the dotted configuration path, so the message can be pasted into a
	// search of the operator's own config file.
	key string
	// why says what the broker does with the setting today, in terms of effect on
	// access rather than in terms of code.
	why string
}

// unenforceablePolicySettings returns every setting in one authentication.policies
// entry that the broker does not act on.
//
// Adding enforcement for one of these means deleting its case here, in the same
// change. That is deliberate: the two lists cannot drift, because there is only
// one list.
func unenforceablePolicySettings(policyPath string, p config.AuthenticationPolicy) []unsupportedPolicySetting {
	var found []unsupportedPolicySetting
	add := func(key, why string) {
		found = append(found, unsupportedPolicySetting{key: policyPath + "." + key, why: why})
	}

	if p.RequireReauthForNewHosts {
		add("require_reauth_for_new_hosts",
			"the broker does not track which hosts an identity has logged into, so no login is ever "+
				"asked to re-authenticate")
	}
	if p.RequireInstitutionalAffiliation {
		add("require_institutional_affiliation",
			"nothing checks the institution claim; a login from an identity with no affiliation is allowed. "+
				"Use require_groups, which is enforced")
	}
	if p.RequireAllocationVerification {
		add("require_allocation_verification",
			"the broker has no allocation system to verify against; every login is allowed regardless of "+
				"allocation")
	}
	if p.RequireProjectMembership != "" {
		add("require_project_membership",
			"project membership is not checked; every login is allowed regardless of project. "+
				"Use require_groups, which is enforced")
	}
	if p.AuditLevel != "" {
		add("audit_level",
			"the audit trail has one verbosity and this does not change it; set audit.log_level instead")
	}
	if p.AllowUnstrustedDevices {
		add("allow_untrusted_devices",
			"device trust is only ever required by require_device_trust, so this grants nothing that is "+
				"not already allowed by leaving require_device_trust unset")
	}
	if p.RequireAdditionalMFA {
		add("require_additional_mfa",
			"the broker cannot tell how an identity authenticated beyond the hardware-key and FIDO methods "+
				"require_device_trust already covers, so no login is ever asked for a second factor")
	}
	if p.NoDataExport {
		add("no_data_export",
			"the broker authenticates logins and does not mediate data movement, so this restricts nothing")
	}
	if p.SessionRecording {
		add("session_recording",
			"the broker does not record sessions and cannot make sshd do so; nothing is recorded")
	}
	if len(p.RequireApprovalFor) > 0 {
		add("require_approval_for",
			"there is no approval step for a login to wait on, so every listed operation proceeds "+
				"unapproved")
	}

	return found
}

// riskPolicyActions are the actions applyRiskPolicies acts on.
//
// (#212) REQUIRE_ADDITIONAL_MFA and REQUIRE_APPROVAL were accepted here and set a
// field nothing read, so a risk policy carrying either was a no-op that looked
// like a control. They are refused for the same reason their per-policy
// equivalents are.
var riskPolicyActions = map[string]bool{
	"DENY": true,
	// LOG is the honest spelling of "notice this and do nothing else": the risk
	// score and its factors are already on every audit record, so a policy whose
	// only purpose is to mark a condition has somewhere to go that is not a lie.
	"LOG": true,
}

// validatePolicySupport refuses a configuration whose access controls the broker
// cannot enforce, and reports every problem at once rather than the first.
//
// Reporting all of them matters: an operator fixing a config by restart-and-see
// would otherwise need one restart per unsupported key, and a broker that will
// not start is a host nobody can log into.
func validatePolicySupport(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}

	var problems []unsupportedPolicySetting

	names := make([]string, 0, len(cfg.Authentication.Policies))
	for name := range cfg.Authentication.Policies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := fmt.Sprintf("authentication.policies.%s", name)
		problems = append(problems, unenforceablePolicySettings(path, cfg.Authentication.Policies[name])...)
	}

	problems = append(problems, unsupportedRiskPolicies(cfg)...)
	problems = append(problems, unsupportedTimeRestrictions(cfg)...)
	problems = append(problems, unsupportedGeoRestrictions(cfg)...)

	if len(problems) == 0 {
		return nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "the configuration sets %d access control(s) this broker cannot enforce, "+
		"and starting would report them as being in force:", len(problems))
	for _, p := range problems {
		fmt.Fprintf(&b, "\n  - %s: %s", p.key, p.why)
	}
	b.WriteString("\n\nRemove or comment out each setting above to start. " +
		"Each one is tracked at https://github.com/scttfrdmn/oidc-pam/issues/212 — " +
		"a release that implements one will accept it again.")
	return fmt.Errorf("%s", b.String())
}

// unsupportedRiskPolicies checks that every risk policy has a condition the
// engine can evaluate and an action it can carry out.
//
// (#213) Both used to fail open. evaluateRiskCondition matched three exact
// strings and returned false for anything else, so the enterprise configuration's
// only hard denial — `risk_score >= 80`, action DENY — never fired, because the
// engine recognized `risk_score >= 70` and nothing else. The action switch had no
// default, so a misspelled action was skipped in silence.
func unsupportedRiskPolicies(cfg *config.Config) []unsupportedPolicySetting {
	var found []unsupportedPolicySetting

	for i, rp := range cfg.Authentication.RiskPolicies {
		path := fmt.Sprintf("authentication.risk_policies[%d]", i)

		if _, err := parseRiskCondition(rp.Condition); err != nil {
			found = append(found, unsupportedPolicySetting{
				key: path + ".condition",
				why: fmt.Sprintf("%v. A condition the engine cannot evaluate never matches, so this "+
					"policy would never apply", err),
			})
		}
		if !riskPolicyActions[rp.Action] {
			actions := make([]string, 0, len(riskPolicyActions))
			for a := range riskPolicyActions {
				actions = append(actions, a)
			}
			sort.Strings(actions)
			found = append(found, unsupportedPolicySetting{
				key: path + ".action",
				why: fmt.Sprintf("%q is not an action this broker performs (it performs %s), so the "+
					"policy would match and then do nothing", rp.Action, strings.Join(actions, " and ")),
			})
		}
	}

	return found
}

// unsupportedTimeRestrictions checks that a time restriction can both match and
// be evaluated.
//
// (#213) allowed_hours that did not parse returned "within the allowed hours" —
// so `09:00-17:00` worked and `9am-5pm` silently allowed every hour of every day.
// An unloadable timezone fell back to UTC, which moves the window by up to half a
// day without saying so.
func unsupportedTimeRestrictions(cfg *config.Config) []unsupportedPolicySetting {
	var found []unsupportedPolicySetting

	for i, r := range cfg.Authentication.TimeBasedPolicies.TimeRestrictions {
		path := fmt.Sprintf("authentication.time_based_policies.time_restrictions[%d]", i)

		if len(r.Providers) == 0 {
			found = append(found, unsupportedPolicySetting{
				key: path + ".providers",
				why: "a restriction with no providers matches no login, so its allowed_hours would never " +
					`apply. Use ["all"], or name the providers it governs`,
			})
		}
		if _, err := parseAllowedHours(r.AllowedHours); err != nil {
			found = append(found, unsupportedPolicySetting{
				key: path + ".allowed_hours",
				why: fmt.Sprintf("%v. An unparseable window used to permit every hour of the day", err),
			})
		}
		if r.Timezone != "" {
			if _, err := time.LoadLocation(r.Timezone); err != nil {
				found = append(found, unsupportedPolicySetting{
					key: path + ".timezone",
					why: fmt.Sprintf("%v. An unloadable timezone used to fall back to UTC, moving the "+
						"allowed window by the offset without saying so", err),
				})
			}
		}
		if len(r.Exceptions) > 0 {
			found = append(found, unsupportedPolicySetting{
				key: path + ".exceptions",
				why: "nothing reads the exception list, so an identity listed here is still subject to " +
					"allowed_hours",
			})
		}
	}

	return found
}

// unsupportedGeoRestrictions checks that a geographic restriction can match, and
// that the broker can tell what country a login came from.
//
// The second check is the one that matters. getCountryFromIP answers "" with no
// GeoIP database configured, and "" is in nobody's allowed_countries — so
// allowed_countries without geoip_database_path denies every login on the host
// with the reason "Access not allowed from country: ". That fails closed, which is
// the right direction, but as a total outage with an empty reason. It is a
// configuration mistake and belongs at startup.
func unsupportedGeoRestrictions(cfg *config.Config) []unsupportedPolicySetting {
	var found []unsupportedPolicySetting

	for i, r := range cfg.Authentication.TimeBasedPolicies.GeoRestrictions {
		path := fmt.Sprintf("authentication.time_based_policies.geo_restrictions[%d]", i)

		if len(r.Providers) == 0 {
			found = append(found, unsupportedPolicySetting{
				key: path + ".providers",
				why: "a restriction with no providers matches no login, so its country lists would never " +
					`apply. Use ["all"], or name the providers it governs`,
			})
		}
		if len(r.AllowedCountries) == 0 && len(r.BlockedCountries) == 0 {
			continue
		}
		if cfg.Authentication.GeoIPDatabasePath == "" {
			found = append(found, unsupportedPolicySetting{
				key: path,
				why: "country restrictions need authentication.geoip_database_path. Without it the broker " +
					"cannot place any login, so an allowed_countries list denies every login on this host " +
					"and a blocked_countries list blocks none",
			})
		}
	}

	return found
}

// parseAllowedHours parses a "HH:MM-HH:MM" window into minutes past midnight.
//
// An empty window means "no restriction" and is valid; anything else must parse.
// Returning the window rather than a bool lets the caller evaluate it without
// re-parsing on every login.
func parseAllowedHours(allowedHours string) (hourWindow, error) {
	if strings.TrimSpace(allowedHours) == "" {
		return hourWindow{unrestricted: true}, nil
	}

	start, end, found := strings.Cut(allowedHours, "-")
	if !found {
		return hourWindow{}, fmt.Errorf("%q is not a window of the form HH:MM-HH:MM", allowedHours)
	}
	startMinute, err := parseClockMinute(start)
	if err != nil {
		return hourWindow{}, fmt.Errorf("%q: start %w", allowedHours, err)
	}
	endMinute, err := parseClockMinute(end)
	if err != nil {
		return hourWindow{}, fmt.Errorf("%q: end %w", allowedHours, err)
	}
	if startMinute == endMinute {
		return hourWindow{}, fmt.Errorf("%q opens and closes at the same minute, which allows nothing",
			allowedHours)
	}
	return hourWindow{startMinute: startMinute, endMinute: endMinute}, nil
}

// hourWindow is a parsed allowed_hours window, in minutes past local midnight.
type hourWindow struct {
	unrestricted bool
	startMinute  int
	endMinute    int
}

// contains reports whether t falls inside the window.
//
// A window whose end is before its start crosses midnight — "22:00-06:00" is a
// night shift, not an empty set — and is the union of the two halves. The old
// code compared against two timestamps built on today's date, so it treated such
// a window as empty and denied every login for a site that configured one.
func (w hourWindow) contains(t time.Time) bool {
	if w.unrestricted {
		return true
	}
	minute := t.Hour()*60 + t.Minute()
	if w.startMinute < w.endMinute {
		return minute >= w.startMinute && minute < w.endMinute
	}
	return minute >= w.startMinute || minute < w.endMinute
}

// parseClockMinute parses "HH:MM" into minutes past midnight.
func parseClockMinute(clock string) (int, error) {
	hh, mm, found := strings.Cut(strings.TrimSpace(clock), ":")
	if !found {
		return 0, fmt.Errorf("%q is not a time of the form HH:MM", clock)
	}
	hour, err := strconv.Atoi(hh)
	if err != nil || hour < 0 || hour > 23 {
		return 0, fmt.Errorf("%q does not have an hour between 00 and 23", clock)
	}
	minute, err := strconv.Atoi(mm)
	if err != nil || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("%q does not have a minute between 00 and 59", clock)
	}
	return hour*60 + minute, nil
}

// riskFlag is a condition about a login that the engine can decide from the
// request and the risk factors it has already computed.
type riskFlag string

// Every flag corresponds to a risk factor calculateRiskScore already computes, so
// a policy can name the specific circumstance it cares about instead of guessing
// which combination of factors adds up to a threshold.
const (
	riskUnusualLocation  riskFlag = "unusual_location"
	riskAfterHours       riskFlag = "after_hours"
	riskUntrustedNetwork riskFlag = "untrusted_network"
	riskUnknownDevice    riskFlag = "unknown_device"
	riskUnknownNetwork   riskFlag = "unknown_network_origin"
)

// riskFlagNames maps every accepted spelling to its canonical flag.
//
// "unknown_network" and "new_device" are aliases because they are the spellings an
// operator is likely to reach for — "new_device" is what the shipped enterprise
// configuration used — and silently not matching a reasonable spelling is the
// defect this whole file exists to remove.
//
// There is deliberately no flag for device trust. Risk policies are evaluated
// before the device flow starts, so at that point the broker has no identity and
// no `amr` claim, and a flag that always read "untrusted" would be worse than not
// offering one. require_device_trust covers it, after the identity is known.
var riskFlagNames = map[riskFlag]riskFlag{
	riskUnusualLocation:  riskUnusualLocation,
	riskAfterHours:       riskAfterHours,
	riskUntrustedNetwork: riskUntrustedNetwork,
	riskUnknownDevice:    riskUnknownDevice,
	riskUnknownNetwork:   riskUnknownNetwork,
	"unknown_network":    riskUnknownNetwork,
	"new_device":         riskUnknownDevice,
}

// riskCondition is a risk-policy condition that has been understood.
//
// (#213) Conditions are parsed once, at startup, and evaluation takes the parsed
// form. That is the point: evaluation has no "unrecognized condition" branch left
// to fall open through, because a condition that cannot be parsed stops the broker
// instead of quietly never matching.
type riskCondition struct {
	// raw is kept for log and error messages, which are read by whoever wrote it.
	raw string

	// Exactly one of the two shapes is populated.

	// scoreOp and scoreWant hold a `risk_score <op> <n>` comparison.
	scoreOp   string
	scoreWant int

	// flags holds a conjunction of named conditions. All must hold.
	flags []riskFlag
}

// riskScoreOps are the comparisons a risk_score condition may use.
var riskScoreOps = map[string]func(score, want int) bool{
	">=": func(score, want int) bool { return score >= want },
	">":  func(score, want int) bool { return score > want },
	"<=": func(score, want int) bool { return score <= want },
	"<":  func(score, want int) bool { return score < want },
	"==": func(score, want int) bool { return score == want },
}

// parseRiskCondition parses a risk policy condition.
//
// Two shapes are accepted:
//
//	risk_score >= 80              a comparison against the computed score
//	unusual_location AND after_hours   a conjunction of named conditions
//
// Whitespace around the operator is optional, so `risk_score>=80` parses; AND is
// case-insensitive. Everything else is an error, and an error stops startup.
func parseRiskCondition(condition string) (riskCondition, error) {
	trimmed := strings.TrimSpace(condition)
	if trimmed == "" {
		return riskCondition{}, fmt.Errorf("the condition is empty")
	}

	if rest, isScore := cutRiskScorePrefix(trimmed); isScore {
		return parseRiskScoreCondition(trimmed, rest)
	}

	// A conjunction of named flags. Splitting on the whole word avoids matching an
	// "AND" inside a future flag name.
	parts := splitConjunction(trimmed)
	parsed := riskCondition{raw: trimmed}
	for _, part := range parts {
		flag := riskFlag(strings.ToLower(strings.TrimSpace(part)))
		canonical, ok := riskFlagNames[flag]
		if !ok {
			return riskCondition{}, fmt.Errorf("%q is not a condition this broker can evaluate "+
				"(it evaluates %s, a conjunction of those joined by AND, or a risk_score comparison "+
				"such as \"risk_score >= 80\")", part, knownRiskFlags())
		}
		parsed.flags = append(parsed.flags, canonical)
	}
	return parsed, nil
}

// cutRiskScorePrefix reports whether the condition is a risk_score comparison and
// returns what follows the field name.
func cutRiskScorePrefix(condition string) (string, bool) {
	const field = "risk_score"
	if !strings.HasPrefix(strings.ToLower(condition), field) {
		return "", false
	}
	return condition[len(field):], true
}

// parseRiskScoreCondition parses the operator and threshold of a risk_score
// comparison.
func parseRiskScoreCondition(raw, rest string) (riskCondition, error) {
	rest = strings.TrimSpace(rest)

	// Two-character operators first, so ">=" is not read as ">" followed by "=80".
	for _, op := range []string{">=", "<=", "==", ">", "<"} {
		if !strings.HasPrefix(rest, op) {
			continue
		}
		threshold := strings.TrimSpace(rest[len(op):])
		want, err := strconv.Atoi(threshold)
		if err != nil {
			return riskCondition{}, fmt.Errorf("%q does not compare risk_score against a whole number "+
				"(%q is not one)", raw, threshold)
		}
		return riskCondition{raw: raw, scoreOp: op, scoreWant: want}, nil
	}

	ops := make([]string, 0, len(riskScoreOps))
	for op := range riskScoreOps {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	return riskCondition{}, fmt.Errorf("%q does not compare risk_score with one of %s",
		raw, strings.Join(ops, ", "))
}

// splitConjunction splits on the word AND, case-insensitively.
func splitConjunction(condition string) []string {
	fields := strings.Fields(condition)
	var parts []string
	var current []string
	for _, field := range fields {
		if strings.EqualFold(field, "AND") {
			parts = append(parts, strings.Join(current, " "))
			current = nil
			continue
		}
		current = append(current, field)
	}
	return append(parts, strings.Join(current, " "))
}

// knownRiskFlags lists the accepted flag names for an error message, so that
// whoever misspelled one is told what the alternatives are.
func knownRiskFlags() string {
	names := make([]string, 0, len(riskFlagNames))
	for name := range riskFlagNames {
		names = append(names, string(name))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// holds reports whether the condition is satisfied by this request.
//
// The engine reads the parsed form, so there is no branch here for a condition it
// does not understand: parseRiskCondition rejected those at startup. A flag
// conjunction with an empty flag list cannot be constructed by the parser, and if
// one somehow were, the loop below leaves `every` true — which is why the parser,
// not this function, is where a malformed condition has to be caught.
func (c riskCondition) holds(pe *PolicyEngine, req *AuthRequest, result *PolicyResult, now time.Time) bool {
	if c.scoreOp != "" {
		compare, ok := riskScoreOps[c.scoreOp]
		if !ok {
			// Unreachable: the parser only ever stores an operator from this map.
			return false
		}
		return compare(result.RiskScore, c.scoreWant)
	}

	for _, flag := range c.flags {
		if !pe.riskFlagHolds(flag, req, now) {
			return false
		}
	}
	return len(c.flags) > 0
}

// riskFlagHolds decides one named condition.
//
// The unknown-origin cases follow calculateRiskScore (#169): a login the broker
// cannot place on any network is not evidence of safety, so untrusted_network
// holds for it. unknown_network_origin exists so a policy can distinguish the two
// when it wants to.
func (pe *PolicyEngine) riskFlagHolds(flag riskFlag, req *AuthRequest, now time.Time) bool {
	switch flag {
	case riskUnusualLocation:
		return pe.isUnusualLocation(req.UserID, req.SourceIP)
	case riskAfterHours:
		return pe.isAfterHours(now)
	case riskUntrustedNetwork:
		return req.SourceIP == "" || !pe.isPrivateIP(req.SourceIP)
	case riskUnknownDevice:
		return req.DeviceID == ""
	case riskUnknownNetwork:
		return req.SourceIP == ""
	default:
		// Unreachable: the parser only ever stores a canonical flag from
		// riskFlagNames. Answering false here would make an unhandled flag a silent
		// no-match, which is exactly the failure this file removes, so a flag added
		// to the map without a case here must be caught in test rather than
		// tolerated at runtime — see TestEveryRiskFlagIsEvaluated.
		return false
	}
}
