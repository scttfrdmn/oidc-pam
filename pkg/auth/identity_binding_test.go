package auth

import (
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

// TestVerifyIdentityBinding covers the C-1 fix: an authenticated OIDC identity
// must map to the requested local username, and the check must fail closed.
func TestVerifyIdentityBinding(t *testing.T) {
	b := &Broker{config: &config.Config{}}

	tests := []struct {
		name      string
		claim     string
		userInfo  *UserInfo
		requested string
		wantErr   bool
	}{
		{
			name:      "preferred_username matches",
			claim:     "preferred_username",
			userInfo:  &UserInfo{Claims: map[string]interface{}{"preferred_username": "alice"}},
			requested: "alice",
			wantErr:   false,
		},
		{
			name:      "email local-part matches requested user",
			claim:     "email",
			userInfo:  &UserInfo{Email: "alice@example.com", Claims: map[string]interface{}{"email": "alice@example.com"}},
			requested: "alice",
			wantErr:   false,
		},
		{
			name:      "case-insensitive match",
			claim:     "preferred_username",
			userInfo:  &UserInfo{Claims: map[string]interface{}{"preferred_username": "Alice"}},
			requested: "alice",
			wantErr:   false,
		},
		{
			name:      "mismatch is rejected (impersonation attempt)",
			claim:     "preferred_username",
			userInfo:  &UserInfo{Claims: map[string]interface{}{"preferred_username": "attacker"}},
			requested: "root",
			wantErr:   true,
		},
		{
			name:      "missing claim configured fails closed",
			claim:     "",
			userInfo:  &UserInfo{Claims: map[string]interface{}{"preferred_username": "alice"}},
			requested: "alice",
			wantErr:   true,
		},
		{
			name:      "claim absent in token fails closed",
			claim:     "preferred_username",
			userInfo:  &UserInfo{Claims: map[string]interface{}{"email": "alice@example.com"}},
			requested: "alice",
			wantErr:   true,
		},
		{
			name:      "empty requested user rejected",
			claim:     "preferred_username",
			userInfo:  &UserInfo{Claims: map[string]interface{}{"preferred_username": "alice"}},
			requested: "",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := b.verifyIdentityBinding(providerWithClaim(tc.claim), tc.userInfo, tc.requested)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected nil error, got: %v", err)
			}
		})
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
