package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

func providerWithClaim(claim string) *OIDCProvider {
	return &OIDCProvider{
		Config: config.OIDCProvider{
			Name:        "test",
			UserMapping: config.UserMapping{UsernameClaim: claim},
		},
	}
}

// providerWithMapping builds a provider with a full user mapping, for the cases
// that turn on username_claim_strip_domain / allowed_email_domains.
func providerWithMapping(claim string, strip bool, domains ...string) *OIDCProvider {
	return &OIDCProvider{
		Config: config.OIDCProvider{
			Name: "test",
			UserMapping: config.UserMapping{
				UsernameClaim:       claim,
				StripEmailDomain:    strip,
				AllowedEmailDomains: domains,
			},
		},
	}
}

// testPasswd is the local passwd table the identity-binding tests run against.
// Injected rather than read from the host so that a uid the suite depends on is
// not whatever the machine running it happens to assign.
var testPasswd = map[string]int{
	"root":     0,
	"daemon":   1,
	"bin":      2,
	"nobody":   65534,
	"alice":    1001,
	"testuser": 1500,
	"bob":      1002,
	"deploy":   400,
	"builder":  999,
}

func testLookupUID(name string) (int, bool, error) {
	uid, ok := testPasswd[name]
	return uid, ok, nil
}

// brokerForBinding returns a broker whose privileged-account guard reads
// testPasswd, optionally allowing some privileged accounts by config.
func brokerForBinding(allowPrivileged ...string) *Broker {
	return &Broker{
		config: &config.Config{
			Authentication: config.AuthenticationConfig{
				AllowPrivilegedAccounts: allowPrivileged,
			},
		},
		lookupLocalUID: testLookupUID,
	}
}

// TestVerifyIdentityBinding covers the C-1 fix: an authenticated OIDC identity
// must map to the requested local username, and the check must fail closed.
func TestVerifyIdentityBinding(t *testing.T) {
	b := brokerForBinding()

	tests := []struct {
		name      string
		provider  *OIDCProvider
		userInfo  *UserInfo
		requested string
		wantErr   bool
	}{
		{
			name:      "preferred_username matches",
			provider:  providerWithClaim("preferred_username"),
			userInfo:  &UserInfo{Claims: map[string]interface{}{"preferred_username": "alice"}},
			requested: "alice",
			wantErr:   false,
		},
		{
			// (#159) This case used to pass with no opt-in at all, and asserting that
			// it did is what made the local-part branch look intentional.
			name:      "email local-part does NOT match by default",
			provider:  providerWithClaim("email"),
			userInfo:  &UserInfo{Email: "alice@example.com", Claims: map[string]interface{}{"email": "alice@example.com"}},
			requested: "alice",
			wantErr:   true,
		},
		{
			name:      "email local-part matches when opted in and the domain is pinned",
			provider:  providerWithMapping("email", true, "example.com"),
			userInfo:  &UserInfo{Email: "alice@example.com", Claims: map[string]interface{}{"email": "alice@example.com"}},
			requested: "alice",
			wantErr:   false,
		},
		{
			name:      "local-part opt-in without pinned domains is refused",
			provider:  providerWithMapping("email", true),
			userInfo:  &UserInfo{Email: "alice@example.com", Claims: map[string]interface{}{"email": "alice@example.com"}},
			requested: "alice",
			wantErr:   true,
		},
		{
			// The guest/B2B case: a different tenant's alice is not this host's alice.
			name:      "local-part from an unpinned domain is refused",
			provider:  providerWithMapping("email", true, "example.com"),
			userInfo:  &UserInfo{Email: "alice@partner.com", Claims: map[string]interface{}{"email": "alice@partner.com"}},
			requested: "alice",
			wantErr:   true,
		},
		{
			name:      "pinned domain comparison is case-insensitive",
			provider:  providerWithMapping("email", true, "Example.COM"),
			userInfo:  &UserInfo{Email: "Alice@EXAMPLE.com", Claims: map[string]interface{}{"email": "Alice@EXAMPLE.com"}},
			requested: "alice",
			wantErr:   false,
		},
		{
			name:      "case-insensitive match",
			provider:  providerWithClaim("preferred_username"),
			userInfo:  &UserInfo{Claims: map[string]interface{}{"preferred_username": "Alice"}},
			requested: "alice",
			wantErr:   false,
		},
		{
			name:      "mismatch is rejected (impersonation attempt)",
			provider:  providerWithClaim("preferred_username"),
			userInfo:  &UserInfo{Claims: map[string]interface{}{"preferred_username": "attacker"}},
			requested: "bob",
			wantErr:   true,
		},
		{
			name:      "missing claim configured fails closed",
			provider:  providerWithClaim(""),
			userInfo:  &UserInfo{Claims: map[string]interface{}{"preferred_username": "alice"}},
			requested: "alice",
			wantErr:   true,
		},
		{
			name:      "claim absent in token fails closed",
			provider:  providerWithClaim("preferred_username"),
			userInfo:  &UserInfo{Claims: map[string]interface{}{"email": "alice@example.com"}},
			requested: "alice",
			wantErr:   true,
		},
		{
			name:      "empty requested user rejected",
			provider:  providerWithClaim("preferred_username"),
			userInfo:  &UserInfo{Claims: map[string]interface{}{"preferred_username": "alice"}},
			requested: "",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := b.verifyIdentityBinding(tc.provider, tc.userInfo, tc.requested)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected nil error, got: %v", err)
			}
		})
	}
}

// TestRootIsNotBindableViaEmailLocalPart is the headline case of #159: with the
// local-part branch unconditional, an identity provider that lets a user choose
// the local part of their address let that user choose to be root.
//
// The attack needed nothing but a mail alias: set the address to root@<anything>,
// run `ssh root@host`, approve the device flow with your own credentials.
// verifyIdentityBinding returned nil, and `auth sufficient pam_oidc.so`
// short-circuited the rest of the stack.
func TestRootIsNotBindableViaEmailLocalPart(t *testing.T) {
	b := brokerForBinding()

	// Every configuration an operator might plausibly have, including the two that
	// try hardest to make this work.
	providers := []struct {
		name     string
		provider *OIDCProvider
	}{
		{"default (no opt-in)", providerWithClaim("email")},
		{"strip-domain opt-in, unpinned", providerWithMapping("email", true)},
		{"strip-domain opt-in, attacker's domain pinned", providerWithMapping("email", true, "evil.tld")},
		{"preferred_username is a UPN, as on Entra ID", providerWithMapping("preferred_username", true, "evil.tld")},
	}

	for _, p := range providers {
		t.Run(p.name, func(t *testing.T) {
			claim := p.provider.Config.UserMapping.UsernameClaim
			userInfo := &UserInfo{
				Email:  "root@evil.tld",
				Claims: map[string]interface{}{claim: "root@evil.tld"},
			}
			err := b.verifyIdentityBinding(p.provider, userInfo, "root")
			if err == nil {
				t.Fatal("root@evil.tld was bound to local root: this is the #159 privilege escalation")
			}
			if !strings.Contains(err.Error(), "uid 0") {
				t.Errorf("refused, but not as a privileged account: %v", err)
			}
		})
	}

	// The same identity claiming a system account is refused for the same reason.
	for _, account := range []string{"daemon", "bin", "builder", "deploy"} {
		t.Run("system account "+account, func(t *testing.T) {
			userInfo := &UserInfo{Claims: map[string]interface{}{"preferred_username": account}}
			if err := b.verifyIdentityBinding(providerWithClaim("preferred_username"), userInfo, account); err == nil {
				t.Errorf("an OIDC identity was bound to system account %q (uid %d)", account, testPasswd[account])
			}
		})
	}
}

// TestPrivilegedAccountGuardIsIndependentOfTheClaim covers the second acceptance
// criterion of #159: the uid guard holds even when the claim is an exact match and
// nothing about the mapping is misconfigured. It is the check that survives the
// operator getting username_claim or allowed_email_domains wrong.
func TestPrivilegedAccountGuardIsIndependentOfTheClaim(t *testing.T) {
	// An exact, unambiguous claim — no domain, no stripping, no ambiguity.
	provider := providerWithClaim("preferred_username")
	userInfo := &UserInfo{Claims: map[string]interface{}{"preferred_username": "deploy"}}

	if err := brokerForBinding().verifyIdentityBinding(provider, userInfo, "deploy"); err == nil {
		t.Fatal("uid 400 was bindable on an exact claim match; the guard must not depend on the claim")
	}

	// And it is overridable, deliberately and by name.
	if err := brokerForBinding("deploy").verifyIdentityBinding(provider, userInfo, "deploy"); err != nil {
		t.Fatalf("allow_privileged_accounts: [deploy] did not permit the binding: %v", err)
	}

	// The override is specific to the account named. Allowing "deploy" does not
	// allow root.
	rootInfo := &UserInfo{Claims: map[string]interface{}{"preferred_username": "root"}}
	if err := brokerForBinding("deploy").verifyIdentityBinding(provider, rootInfo, "root"); err == nil {
		t.Error("allow_privileged_accounts: [deploy] also permitted root")
	}
	if err := brokerForBinding("root").verifyIdentityBinding(provider, rootInfo, "root"); err != nil {
		t.Errorf("allow_privileged_accounts: [root] did not permit root: %v", err)
	}
}

// TestUnprivilegedAndUnknownAccountsStillBind guards against the fix locking out
// the logins it is not about: ordinary users, and accounts that do not exist
// locally (where there is no privilege to escalate to and the login cannot succeed
// anyway).
func TestUnprivilegedAndUnknownAccountsStillBind(t *testing.T) {
	b := brokerForBinding()
	provider := providerWithClaim("preferred_username")

	for _, account := range []string{"alice", "bob", "nobody", "no-such-local-account"} {
		userInfo := &UserInfo{Claims: map[string]interface{}{"preferred_username": account}}
		if err := b.verifyIdentityBinding(provider, userInfo, account); err != nil {
			t.Errorf("binding %q was refused: %v", account, err)
		}
	}
}

// TestPrivilegedGuardFailsClosedOnLookupError: if we cannot tell whether the
// account is privileged, we have not performed the check, so we do not pass it.
func TestPrivilegedGuardFailsClosedOnLookupError(t *testing.T) {
	b := &Broker{
		config: &config.Config{},
		lookupLocalUID: func(string) (int, bool, error) {
			return 0, false, errNoPasswd
		},
	}
	userInfo := &UserInfo{Claims: map[string]interface{}{"preferred_username": "alice"}}
	if err := b.verifyIdentityBinding(providerWithClaim("preferred_username"), userInfo, "alice"); err == nil {
		t.Fatal("a passwd lookup failure was treated as 'not privileged'")
	}
}

// TestRealLookupResolvesRoot checks the production lookup against the one uid that
// is 0 on every Unix, so the injected table in the tests above is not the only
// thing ever exercised.
func TestRealLookupResolvesRoot(t *testing.T) {
	uid, exists, err := lookupLocalUID("root")
	if err != nil {
		t.Fatalf("lookupLocalUID(root): %v", err)
	}
	if !exists || uid != 0 {
		t.Fatalf("lookupLocalUID(root) = (%d, %v), want (0, true)", uid, exists)
	}

	// A name that cannot exist must be reported as absent, not as an error: that
	// distinction is what keeps unknown accounts bindable.
	if _, exists, err := lookupLocalUID("oidc-pam-no-such-user-159"); err != nil || exists {
		t.Fatalf("lookup of a nonexistent user = (exists=%v, err=%v), want (false, nil)", exists, err)
	}
}

// TestVerifyRequiredGroups covers the H-1 fix.
func TestVerifyRequiredGroups(t *testing.T) {
	tests := []struct {
		name     string
		required []string
		have     []string
		wantErr  bool
	}{
		{"no groups required", nil, []string{"x"}, false},
		{"member satisfies", []string{"hpc-admins"}, []string{"a", "hpc-admins"}, false},
		{"missing required group denied", []string{"hpc-admins"}, []string{"users"}, true},
		{"all required present", []string{"a", "b"}, []string{"a", "b", "c"}, false},
		{"one of several missing denied", []string{"a", "b"}, []string{"a"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &Broker{config: &config.Config{
				Authentication: config.AuthenticationConfig{RequireGroups: tc.required},
			}}
			err := b.verifyRequiredGroups(tc.required, tc.have)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected nil error, got: %v", err)
			}
		})
	}
}

// errNoPasswd stands in for a passwd lookup that failed for a reason other than
// "no such user" — an unreachable LDAP/SSSD backend, most realistically.
var errNoPasswd = errors.New("passwd backend unavailable")
