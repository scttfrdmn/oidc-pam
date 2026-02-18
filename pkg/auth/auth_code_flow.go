package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
	"golang.org/x/oauth2"
)

// AuthCodeFlowState holds the state needed to complete an authorization code flow.
type AuthCodeFlowState struct {
	AuthURL string
	State   string
	Nonce   string
}

// StartAuthCodeFlow initiates an authorization code flow with CSRF state and
// nonce parameters for replay-attack protection.
func (p *OIDCProvider) StartAuthCodeFlow(redirectURL string) (*AuthCodeFlowState, error) {
	nonce, err := security.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	state, err := security.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Temporarily set redirect URL for this flow
	cfg := *p.OAuth2Config
	cfg.RedirectURL = redirectURL

	authURL := cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
	)

	log.Debug().
		Str("provider", p.Name).
		Str("redirect_url", redirectURL).
		Msg("Authorization code flow initiated")

	return &AuthCodeFlowState{
		AuthURL: authURL,
		State:   state,
		Nonce:   nonce,
	}, nil
}

// ExchangeCodeForToken exchanges an authorization code for tokens and verifies
// that the ID token nonce matches expectedNonce.
func (p *OIDCProvider) ExchangeCodeForToken(ctx context.Context, code, expectedNonce string) (*Token, error) {
	if expectedNonce == "" {
		return nil, fmt.Errorf("expected nonce must not be empty")
	}

	oauth2Token, err := p.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("no id_token in token response")
	}

	// Create a per-request verifier for signature and standard claim checks.
	verifier := p.Provider.Verifier(&oidc.Config{
		ClientID:             p.Config.ClientID,
		SupportedSigningAlgs: []string{"RS256", "ES256"},
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// The go-oidc library exposes the nonce but does not verify it.
	// We must check it ourselves to prevent replay attacks.
	if idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("ID token nonce mismatch: expected %q, got %q", expectedNonce, idToken.Nonce)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	if err := p.validateIDTokenClaims(claims); err != nil {
		return nil, fmt.Errorf("ID token claim validation failed: %w", err)
	}

	token := &Token{
		AccessToken:  oauth2Token.AccessToken,
		RefreshToken: oauth2Token.RefreshToken,
		IDToken:      rawIDToken,
		TokenType:    oauth2Token.TokenType,
		ExpiresAt:    oauth2Token.Expiry,
		Fingerprint:  p.generateTokenFingerprint(oauth2Token.AccessToken),
		Claims:       claims,
	}

	log.Debug().
		Str("provider", p.Name).
		Str("token_type", token.TokenType).
		Time("expires_at", token.ExpiresAt).
		Msg("Authorization code exchange completed")

	return token, nil
}
