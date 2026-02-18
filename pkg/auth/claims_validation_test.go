package auth

import (
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

func TestValidateIDTokenClaims_AuthTimeRequiredButMissing(t *testing.T) {
	provider := &OIDCProvider{
		securityConfig: config.SecurityConfig{
			RequireAuthTime: true,
		},
	}

	claims := map[string]interface{}{
		"sub": "user-123",
	}

	err := provider.validateIDTokenClaims(claims)
	if err == nil {
		t.Error("expected error when auth_time is required but missing")
	}
}

func TestValidateIDTokenClaims_AuthTimeRequiredAndPresent(t *testing.T) {
	provider := &OIDCProvider{
		securityConfig: config.SecurityConfig{
			RequireAuthTime: true,
		},
	}

	claims := map[string]interface{}{
		"sub":       "user-123",
		"auth_time": float64(time.Now().Unix()),
	}

	err := provider.validateIDTokenClaims(claims)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateIDTokenClaims_TokenTooOld(t *testing.T) {
	provider := &OIDCProvider{
		securityConfig: config.SecurityConfig{
			MaxTokenAge:        1 * time.Hour,
			ClockSkewTolerance: 5 * time.Minute,
		},
	}

	// auth_time is 2 hours ago, which exceeds MaxTokenAge + ClockSkewTolerance
	claims := map[string]interface{}{
		"sub":       "user-123",
		"auth_time": float64(time.Now().Add(-2 * time.Hour).Unix()),
	}

	err := provider.validateIDTokenClaims(claims)
	if err == nil {
		t.Error("expected error when token is too old")
	}
}

func TestValidateIDTokenClaims_TokenAgeWithinLimit(t *testing.T) {
	provider := &OIDCProvider{
		securityConfig: config.SecurityConfig{
			MaxTokenAge:        1 * time.Hour,
			ClockSkewTolerance: 5 * time.Minute,
		},
	}

	// auth_time is 30 minutes ago, well within limit
	claims := map[string]interface{}{
		"sub":       "user-123",
		"auth_time": float64(time.Now().Add(-30 * time.Minute).Unix()),
	}

	err := provider.validateIDTokenClaims(claims)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateIDTokenClaims_ClockSkewToleranceRespected(t *testing.T) {
	provider := &OIDCProvider{
		securityConfig: config.SecurityConfig{
			MaxTokenAge:        1 * time.Hour,
			ClockSkewTolerance: 10 * time.Minute,
		},
	}

	// auth_time is 65 minutes ago — exceeds MaxTokenAge but within MaxTokenAge + ClockSkewTolerance
	claims := map[string]interface{}{
		"sub":       "user-123",
		"auth_time": float64(time.Now().Add(-65 * time.Minute).Unix()),
	}

	err := provider.validateIDTokenClaims(claims)
	if err != nil {
		t.Errorf("unexpected error (clock skew should allow this): %v", err)
	}
}

func TestValidateIDTokenClaims_NoRequirements(t *testing.T) {
	provider := &OIDCProvider{
		securityConfig: config.SecurityConfig{},
	}

	// No auth_time requirement, no max token age — should pass regardless
	claims := map[string]interface{}{
		"sub": "user-123",
	}

	err := provider.validateIDTokenClaims(claims)
	if err != nil {
		t.Errorf("unexpected error with no requirements: %v", err)
	}

	// Also passes with auth_time present but no requirements
	claims["auth_time"] = float64(time.Now().Add(-48 * time.Hour).Unix())
	err = provider.validateIDTokenClaims(claims)
	if err != nil {
		t.Errorf("unexpected error with no requirements and old auth_time: %v", err)
	}
}

func TestValidateIDTokenClaims_InvalidAuthTimeType(t *testing.T) {
	provider := &OIDCProvider{
		securityConfig: config.SecurityConfig{
			MaxTokenAge: 1 * time.Hour,
		},
	}

	claims := map[string]interface{}{
		"sub":       "user-123",
		"auth_time": "not-a-number",
	}

	err := provider.validateIDTokenClaims(claims)
	if err == nil {
		t.Error("expected error for invalid auth_time type")
	}
}
