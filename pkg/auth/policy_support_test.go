package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// TestEveryUnenforceablePolicySettingIsRefusedByName is the acceptance test for
// #212. Each of these ten settings parsed, loaded, appeared in the configuration
// the broker was running, and was read by nothing — so a policy that set
// `session_recording: true` described a control that did not exist and the login
// proceeded exactly as if it had not been set. Three shipped provider templates and
// the enterprise production template between them set nine of the ten.
//
// The test asserts two things per setting: that the broker refuses to start on it,
// and that the refusal names it. The second is what makes the error actionable —
// an operator whose host will not accept logins needs to know which line to delete,
// not that "something is unsupported".
func TestEveryUnenforceablePolicySettingIsRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		key    string
		policy config.AuthenticationPolicy
	}{
		{"require_reauth_for_new_hosts", config.AuthenticationPolicy{RequireReauthForNewHosts: true}},
		{"require_institutional_affiliation", config.AuthenticationPolicy{RequireInstitutionalAffiliation: true}},
		{"require_allocation_verification", config.AuthenticationPolicy{RequireAllocationVerification: true}},
		{"require_project_membership", config.AuthenticationPolicy{RequireProjectMembership: "nsf-climate"}},
		{"audit_level", config.AuthenticationPolicy{AuditLevel: "detailed"}},
		{"allow_untrusted_devices", config.AuthenticationPolicy{AllowUnstrustedDevices: true}},
		{"require_additional_mfa", config.AuthenticationPolicy{RequireAdditionalMFA: true}},
		{"no_data_export", config.AuthenticationPolicy{NoDataExport: true}},
		{"session_recording", config.AuthenticationPolicy{SessionRecording: true}},
		{"require_approval_for", config.AuthenticationPolicy{RequireApprovalFor: []string{"admin-actions"}}},
	} {
		t.Run(tc.key, func(t *testing.T) {
			cfg := &config.Config{
				Authentication: config.AuthenticationConfig{
					Policies: map[string]config.AuthenticationPolicy{"production": tc.policy},
				},
			}

			err := validatePolicySupport(cfg)
			if err == nil {
				t.Fatalf("a policy setting %s was accepted; nothing enforces it, so the broker would "+
					"report a control it does not apply (#212)", tc.key)
			}
			// The dotted path, so the message can be searched for in the operator's
			// own file.
			want := "authentication.policies.production." + tc.key
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the startup error does not name %s, so it does not say which line to remove:\n%v",
					want, err)
			}
		})
	}
}

// TestEveryEnforcedPolicySettingIsAccepted is the other half, and it is the one
// that stops the refusal from growing: the four settings the broker does enforce
// must go on working together in one policy.
func TestEveryEnforcedPolicySettingIsAccepted(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			Policies: map[string]config.AuthenticationPolicy{
				"default": {
					RequireGroups:      []string{"production-access"},
					MaxSessionDuration: 2 * time.Hour,
					RequireDeviceTrust: true,
					IPWhitelist:        []string{"10.0.0.0/8"},
				},
			},
		},
	}

	if err := validatePolicySupport(cfg); err != nil {
		t.Fatalf("a policy setting only the four enforced settings was refused: %v", err)
	}
}

// TestUnenforceableSettingsAreReportedTogether covers the reason validation
// collects rather than returning the first problem. An operator fixing this by
// restart-and-see would need one restart per key, and between each restart the host
// accepts no logins at all.
func TestUnenforceableSettingsAreReportedTogether(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			Policies: map[string]config.AuthenticationPolicy{
				"production": {AuditLevel: "detailed", SessionRecording: true, NoDataExport: true},
				"staging":    {RequireAdditionalMFA: true},
			},
		},
	}

	err := validatePolicySupport(cfg)
	if err == nil {
		t.Fatal("four unenforceable settings were accepted")
	}
	for _, want := range []string{
		"authentication.policies.production.audit_level",
		"authentication.policies.production.session_recording",
		"authentication.policies.production.no_data_export",
		"authentication.policies.staging.require_additional_mfa",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the startup error omits %s, so fixing this config takes one restart per key:\n%v",
				want, err)
		}
	}
}

// TestParseRiskCondition pins the vocabulary of #213. Before this, an unparseable
// condition reached an evaluator whose switch had a default that answered false: a
// misspelled flag or an operator the code did not handle meant the policy silently
// never matched, so a `DENY` on high risk did not deny. Parsing at startup is what
// removes that branch.
func TestParseRiskCondition(t *testing.T) {
	for _, tc := range []struct {
		condition string
		wantOp    string
		wantWant  int
		wantFlags []riskFlag
	}{
		// The spelling the shipped enterprise config uses, which had to keep working.
		{condition: "risk_score >= 80", wantOp: ">=", wantWant: 80},
		{condition: "risk_score>=80", wantOp: ">=", wantWant: 80},
		{condition: "risk_score < 20", wantOp: "<", wantWant: 20},
		{condition: "risk_score == 0", wantOp: "==", wantWant: 0},
		{condition: "unusual_location", wantFlags: []riskFlag{riskUnusualLocation}},
		{
			condition: "unusual_location AND after_hours",
			wantFlags: []riskFlag{riskUnusualLocation, riskAfterHours},
		},
		// AND is case-insensitive, and the flag names are lowercased.
		{
			condition: "UNUSUAL_LOCATION and After_Hours",
			wantFlags: []riskFlag{riskUnusualLocation, riskAfterHours},
		},
		// The two aliases resolve to their canonical flag, so evaluation has one
		// name per condition however it was written.
		{condition: "new_device", wantFlags: []riskFlag{riskUnknownDevice}},
		{condition: "unknown_network", wantFlags: []riskFlag{riskUnknownNetwork}},
	} {
		t.Run(tc.condition, func(t *testing.T) {
			parsed, err := parseRiskCondition(tc.condition)
			if err != nil {
				t.Fatalf("parseRiskCondition(%q): %v", tc.condition, err)
			}
			if parsed.scoreOp != tc.wantOp || parsed.scoreWant != tc.wantWant {
				t.Errorf("score comparison = %q %d, want %q %d",
					parsed.scoreOp, parsed.scoreWant, tc.wantOp, tc.wantWant)
			}
			if len(parsed.flags) != len(tc.wantFlags) {
				t.Fatalf("flags = %v, want %v", parsed.flags, tc.wantFlags)
			}
			for i, flag := range tc.wantFlags {
				if parsed.flags[i] != flag {
					t.Errorf("flags[%d] = %q, want %q", i, parsed.flags[i], flag)
				}
			}
		})
	}
}

// TestParseRiskConditionRejectsWhatItCannotEvaluate covers the conditions that used
// to be accepted and then never matched. Two of them are verbatim from
// configs/production/broker-enterprise.yaml, where they named four flags — and one
// action — that have never existed in this codebase, so both policies were dead
// text in a file recommended as a production template.
func TestParseRiskConditionRejectsWhatItCannotEvaluate(t *testing.T) {
	for _, tc := range []struct{ name, condition string }{
		{"empty", ""},
		{"whitespace", "   "},
		{"misspelled flag", "unusual_locaton"},
		{"flags that never existed", "new_device AND production_access"},
		{"more flags that never existed", "contractor AND sensitive_data"},
		{"one good flag and one bad", "after_hours AND sensitive_data"},
		{"unsupported field", "trust_score >= 80"},
		{"no operator", "risk_score 80"},
		{"non-numeric threshold", "risk_score >= high"},
		{"operator the engine does not have", "risk_score != 80"},
		{"nothing after AND", "after_hours AND"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseRiskCondition(tc.condition)
			if err == nil {
				t.Fatalf("parseRiskCondition(%q) was accepted as %+v; an accepted condition the engine "+
					"cannot evaluate never matches, so its DENY never denies (#213)", tc.condition, parsed)
			}
		})
	}
}

// TestEveryRiskFlagIsEvaluated is the guard riskFlagHolds' default branch points
// at. That default answers false, so a flag added to riskFlagNames without a case
// in riskFlagHolds would be accepted at startup and then never hold — the same
// silent no-match this change exists to remove, reintroduced by an ordinary
// omission.
//
// It works by giving each flag a request that must make it true and one that must
// make it false. A flag with no case answers false to both, and fails here.
func TestEveryRiskFlagIsEvaluated(t *testing.T) {
	// A location history the user is not in, so isUnusualLocation can answer true.
	// The engine records nothing for "known-user" until RecordLocation is called.
	engine, err := NewPolicyEngine(&config.Config{})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	defer engine.Close()
	engine.RecordLocation("known-user", "10.1.2.3")

	afterHours := time.Date(2026, 3, 4, 2, 30, 0, 0, time.Local)
	businessHours := time.Date(2026, 3, 4, 11, 0, 0, 0, time.Local)

	// One case per canonical flag. Keyed by flag so a new canonical flag with no
	// entry here is caught by the completeness check below.
	cases := map[riskFlag]struct {
		holds    *AuthRequest
		holdsAt  time.Time
		notHolds *AuthRequest
		notAt    time.Time
	}{
		riskUnusualLocation: {
			holds:    &AuthRequest{UserID: "known-user", SourceIP: "203.0.113.9"},
			holdsAt:  businessHours,
			notHolds: &AuthRequest{UserID: "known-user", SourceIP: "10.1.2.3"},
			notAt:    businessHours,
		},
		riskAfterHours: {
			holds:    &AuthRequest{UserID: "u", SourceIP: "10.0.0.1"},
			holdsAt:  afterHours,
			notHolds: &AuthRequest{UserID: "u", SourceIP: "10.0.0.1"},
			notAt:    businessHours,
		},
		riskUntrustedNetwork: {
			holds:    &AuthRequest{UserID: "u", SourceIP: "203.0.113.9"},
			holdsAt:  businessHours,
			notHolds: &AuthRequest{UserID: "u", SourceIP: "10.0.0.1"},
			notAt:    businessHours,
		},
		riskUnknownDevice: {
			holds:    &AuthRequest{UserID: "u", SourceIP: "10.0.0.1"},
			holdsAt:  businessHours,
			notHolds: &AuthRequest{UserID: "u", SourceIP: "10.0.0.1", DeviceID: "laptop-7"},
			notAt:    businessHours,
		},
		riskUnknownNetwork: {
			holds:    &AuthRequest{UserID: "u", SourceIP: ""},
			holdsAt:  businessHours,
			notHolds: &AuthRequest{UserID: "u", SourceIP: "10.0.0.1"},
			notAt:    businessHours,
		},
	}

	// Every canonical flag in the map an operator's condition is resolved against
	// must have a case here, so adding a flag forces adding its evaluation test.
	for _, canonical := range riskFlagNames {
		if _, covered := cases[canonical]; !covered {
			t.Errorf("riskFlagNames resolves to %q, which no case here exercises; a flag with no "+
				"case in riskFlagHolds is accepted at startup and then never holds", canonical)
		}
	}

	for flag, tc := range cases {
		t.Run(string(flag), func(t *testing.T) {
			if !engine.riskFlagHolds(flag, tc.holds, tc.holdsAt) {
				t.Errorf("riskFlagHolds(%q) is false for a request that should satisfy it; if the flag "+
					"has no case in riskFlagHolds, a policy naming it never matches", flag)
			}
			if engine.riskFlagHolds(flag, tc.notHolds, tc.notAt) {
				t.Errorf("riskFlagHolds(%q) is true for a request that should not satisfy it", flag)
			}
		})
	}
}

// TestUntrustedNetworkHoldsForAnUnknownOrigin pins the direction the ambiguous case
// falls, following #169: a login the broker cannot place on any network is not
// evidence of a safe one, so the flag holds. Getting this backwards would let a
// login that reports no source address slip past every untrusted_network policy.
func TestUntrustedNetworkHoldsForAnUnknownOrigin(t *testing.T) {
	engine, err := NewPolicyEngine(&config.Config{})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	defer engine.Close()

	req := &AuthRequest{UserID: "u"} // no SourceIP: a console login, or a PAM_RHOST that is a name
	if !engine.riskFlagHolds(riskUntrustedNetwork, req, time.Now()) {
		t.Error("untrusted_network is false for a login with no source address; an unknown origin is " +
			"not evidence of a trusted one (#169)")
	}
}

// TestRiskConditionWithNoFlagsCannotHold covers holds()'s trailing
// `len(c.flags) > 0`. Without it an empty conjunction — every flag loop trivially
// satisfied — would return true, so a policy whose condition failed to yield any
// flag would match every single login. For a DENY policy that locks out the host.
func TestRiskConditionWithNoFlagsCannotHold(t *testing.T) {
	engine, err := NewPolicyEngine(&config.Config{})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	defer engine.Close()

	empty := riskCondition{raw: "constructed with no flags"}
	if empty.holds(engine, &AuthRequest{UserID: "u"}, &PolicyResult{RiskScore: 0}, time.Now()) {
		t.Error("a condition with no flags and no score comparison holds, so it would match every login")
	}
}

// TestRiskPolicyActions pins the two actions the broker performs. The other two
// were accepted, set a field nothing read, and let the login proceed exactly as if
// the policy had not matched — so a config full of REQUIRE_APPROVAL described an
// approval workflow that has never existed.
func TestRiskPolicyActions(t *testing.T) {
	for action, want := range map[string]bool{
		"DENY":                   true,
		"LOG":                    true,
		"REQUIRE_ADDITIONAL_MFA": false,
		"REQUIRE_APPROVAL":       false,
		"ALLOW":                  false,
		"deny":                   false, // the spelling is upper case; a near miss must not pass
	} {
		cfg := &config.Config{
			Authentication: config.AuthenticationConfig{
				RiskPolicies: []config.RiskPolicy{{Condition: "risk_score >= 80", Action: action}},
			},
		}
		err := validatePolicySupport(cfg)
		if want && err != nil {
			t.Errorf("risk action %q was refused: %v", action, err)
		}
		if !want && err == nil {
			t.Errorf("risk action %q was accepted; the broker does not perform it, so the policy would "+
				"match and then do nothing (#212)", action)
		}
	}
}

// TestParseAllowedHoursSpansMidnight is the case a comparison against two same-day
// timestamps gets wrong. A window of 22:00-06:00 is the union of two halves of the
// clock; treating it as one range makes it empty, so a restriction meant to permit
// overnight access denies all of it — and a restriction meant to *confine* access to
// those hours permits none.
func TestParseAllowedHoursSpansMidnight(t *testing.T) {
	window, err := parseAllowedHours("22:00-06:00")
	if err != nil {
		t.Fatalf("parseAllowedHours: %v", err)
	}

	for _, tc := range []struct {
		hour, minute int
		want         bool
	}{
		{23, 0, true},  // before midnight
		{0, 30, true},  // after midnight
		{5, 59, true},  // last minute in
		{6, 0, false},  // the end is exclusive
		{12, 0, false}, // the middle of the day is out
		{21, 59, false},
		{22, 0, true}, // the start is inclusive
	} {
		at := time.Date(2026, 3, 4, tc.hour, tc.minute, 0, 0, time.Local)
		if got := window.contains(at); got != tc.want {
			t.Errorf("22:00-06:00 contains %02d:%02d = %v, want %v", tc.hour, tc.minute, got, tc.want)
		}
	}
}

// TestParseAllowedHours covers the ordinary window and the empty one, which means
// "no restriction" rather than "no hours".
func TestParseAllowedHours(t *testing.T) {
	window, err := parseAllowedHours("08:00-18:00")
	if err != nil {
		t.Fatalf("parseAllowedHours: %v", err)
	}
	for _, tc := range []struct {
		hour int
		want bool
	}{{7, false}, {8, true}, {17, true}, {18, false}, {23, false}} {
		at := time.Date(2026, 3, 4, tc.hour, 0, 0, 0, time.Local)
		if got := window.contains(at); got != tc.want {
			t.Errorf("08:00-18:00 contains %02d:00 = %v, want %v", tc.hour, got, tc.want)
		}
	}

	unrestricted, err := parseAllowedHours("")
	if err != nil {
		t.Fatalf("parseAllowedHours(\"\"): %v", err)
	}
	if !unrestricted.contains(time.Date(2026, 3, 4, 3, 0, 0, 0, time.Local)) {
		t.Error("an unset allowed_hours excludes 03:00; it must mean no restriction, not no hours")
	}
}

// TestParseAllowedHoursRejectsWhatItCannotRead covers the reason this is parsed at
// startup. An unreadable window used to leave the restriction inert, so an operator
// who wrote "8am-6pm" got no time restriction at all and no indication of it.
func TestParseAllowedHoursRejectsWhatItCannotRead(t *testing.T) {
	for _, spec := range []string{
		"8am-6pm",
		"08:00",
		"08:00-",
		"-18:00",
		"08:00-18:00-20:00",
		"24:00-06:00",
		"08:60-18:00",
		"eight-six",
	} {
		if window, err := parseAllowedHours(spec); err == nil {
			t.Errorf("parseAllowedHours(%q) was accepted as %+v; an allowed_hours the broker cannot "+
				"read used to leave the restriction inert (#213)", spec, window)
		}
	}
}

// TestTimeRestrictionNeedsAProviderScope and the geo equivalent in
// policy_geoip_test.go cover the same defect from #213: a restriction naming a
// provider was skipped unless its list contained the literal "all", so every
// provider-scoped restriction in every config was inert. Scoping works now, which
// makes an empty list a configuration error rather than a silent no-op.
func TestTimeRestrictionNeedsAProviderScope(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TimeBasedPolicies: config.TimeBasedPolicies{
				TimeRestrictions: []config.TimeRestriction{
					{AllowedHours: "08:00-18:00"},
				},
			},
		},
	}

	err := validatePolicySupport(cfg)
	if err == nil {
		t.Fatal("a time restriction with an empty providers list was accepted; it applies to no " +
			"provider, so it restricts nothing (#212)")
	}
	if !strings.Contains(err.Error(), "providers") {
		t.Errorf("the startup error does not name the empty providers list: %v", err)
	}
}

// TestTimeRestrictionExceptionsAreRefused covers a setting that made the
// restriction weaker than it read: exceptions parsed and nothing read it, so a
// listed group was still refused outside the window. Refusing to start is the only
// answer that does not misreport which identities the window applies to.
func TestTimeRestrictionExceptionsAreRefused(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TimeBasedPolicies: config.TimeBasedPolicies{
				TimeRestrictions: []config.TimeRestriction{{
					Providers:    []string{"all"},
					AllowedHours: "08:00-18:00",
					Exceptions:   []string{"emergency-access"},
				}},
			},
		},
	}

	err := validatePolicySupport(cfg)
	if err == nil {
		t.Fatal("a time restriction with exceptions was accepted; the exception is not applied, so a " +
			"listed group is still refused outside the window (#212)")
	}
	if !strings.Contains(err.Error(), "exceptions") {
		t.Errorf("the startup error does not name exceptions: %v", err)
	}
}

// TestTimeRestrictionTimezoneMustLoad covers the last of the compile-at-startup
// changes. An unloadable timezone left the window compared against the wrong clock
// — the broker's own — so a restriction written for America/New_York silently ran
// in UTC, five hours out.
func TestTimeRestrictionTimezoneMustLoad(t *testing.T) {
	cfg := &config.Config{
		Authentication: config.AuthenticationConfig{
			TimeBasedPolicies: config.TimeBasedPolicies{
				TimeRestrictions: []config.TimeRestriction{{
					Providers:    []string{"all"},
					AllowedHours: "08:00-18:00",
					Timezone:     "America/Notaplace",
				}},
			},
		},
	}

	if err := validatePolicySupport(cfg); err == nil {
		t.Fatal("a time restriction naming a timezone the host cannot load was accepted; the window " +
			"would be compared against the broker's own clock instead (#213)")
	}
}

// TestRestrictionApplies covers the scoping fix itself: "all", an exact name, a
// case-different name, a non-match, and the empty list that used to be the only
// thing every provider-scoped restriction effectively had.
func TestRestrictionApplies(t *testing.T) {
	for _, tc := range []struct {
		name      string
		providers []string
		provider  string
		want      bool
	}{
		{"all matches anything", []string{"all"}, "corporate", true},
		{"all matches an unnamed provider", []string{"all"}, "", true},
		{"exact name", []string{"contractors"}, "contractors", true},
		{"case-insensitive name", []string{"Contractors"}, "contractors", true},
		{"one of several", []string{"corporate", "contractors"}, "contractors", true},
		{"a different provider", []string{"contractors"}, "corporate", false},
		{"empty list matches nothing", nil, "contractors", false},
		// A restriction naming a provider must not apply when the broker does not
		// know which provider is in play: matching on "" would apply every
		// provider-scoped restriction at once.
		{"named provider, unknown provider name", []string{"contractors"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := restrictionApplies(tc.providers, tc.provider); got != tc.want {
				t.Errorf("restrictionApplies(%v, %q) = %v, want %v",
					tc.providers, tc.provider, got, tc.want)
			}
		})
	}
}
