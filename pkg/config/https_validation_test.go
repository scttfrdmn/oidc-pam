package config

import (
	"os"
	"testing"
)

// TestValidateHTTPSEndpoint covers L-8: OIDC endpoints must use HTTPS in
// production, with empty allowed and http tolerated only in development mode.
func TestValidateHTTPSEndpoint(t *testing.T) {
	// Ensure we are not in development mode for the strict cases.
	old := os.Getenv("OIDC_AUTH_DEV")
	_ = os.Unsetenv("OIDC_AUTH_DEV")
	defer func() { _ = os.Setenv("OIDC_AUTH_DEV", old) }()

	if err := validateHTTPSEndpoint(""); err != nil {
		t.Errorf("empty endpoint should be allowed, got: %v", err)
	}
	if err := validateHTTPSEndpoint("https://idp.example.com"); err != nil {
		t.Errorf("https endpoint should be allowed, got: %v", err)
	}
	if err := validateHTTPSEndpoint("http://idp.example.com"); err == nil {
		t.Error("http endpoint should be rejected in production")
	}

	// In development mode http is tolerated.
	_ = os.Setenv("OIDC_AUTH_DEV", "true")
	if err := validateHTTPSEndpoint("http://localhost:8080"); err != nil {
		t.Errorf("http should be allowed in dev mode, got: %v", err)
	}
}
