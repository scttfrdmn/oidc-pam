package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"golang.org/x/oauth2"
)

func TestStartAuthCodeFlow(t *testing.T) {
	provider := &OIDCProvider{
		Name: "test-provider",
		Config: config.OIDCProvider{
			Name:     "test-provider",
			Issuer:   "https://example.com",
			ClientID: "test-client",
			Scopes:   []string{"openid", "profile"},
		},
		OAuth2Config: &oauth2.Config{
			ClientID: "test-client",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://example.com/authorize",
				TokenURL: "https://example.com/token",
			},
			Scopes: []string{"openid", "profile"},
		},
	}

	redirectURL := "http://localhost:8080/callback"
	flowState, err := provider.StartAuthCodeFlow(redirectURL)
	if err != nil {
		t.Fatalf("StartAuthCodeFlow failed: %v", err)
	}

	// Verify all fields are populated
	if flowState.AuthURL == "" {
		t.Error("AuthURL should not be empty")
	}
	if flowState.State == "" {
		t.Error("State should not be empty")
	}
	if flowState.Nonce == "" {
		t.Error("Nonce should not be empty")
	}

	// Verify AuthURL contains nonce and state params
	if !strings.Contains(flowState.AuthURL, "nonce=") {
		t.Error("AuthURL should contain nonce parameter")
	}
	if !strings.Contains(flowState.AuthURL, "state=") {
		t.Error("AuthURL should contain state parameter")
	}
	if !strings.Contains(flowState.AuthURL, "redirect_uri=") {
		t.Error("AuthURL should contain redirect_uri parameter")
	}

	// Verify uniqueness across calls
	flowState2, err := provider.StartAuthCodeFlow(redirectURL)
	if err != nil {
		t.Fatalf("second StartAuthCodeFlow failed: %v", err)
	}
	if flowState.State == flowState2.State {
		t.Error("State should be unique across calls")
	}
	if flowState.Nonce == flowState2.Nonce {
		t.Error("Nonce should be unique across calls")
	}
}

// testOIDCServer sets up an httptest server that serves OIDC discovery, JWKS,
// and token endpoints. It returns the server and the RSA key used for signing.
func testOIDCServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// We need the server URL which is set after creation, so we
		// read the Host header to reconstruct it.
		scheme := "http"
		baseURL := scheme + "://" + r.Host
		disc := map[string]interface{}{
			"issuer":                                baseURL,
			"authorization_endpoint":                baseURL + "/authorize",
			"token_endpoint":                        baseURL + "/token",
			"jwks_uri":                              baseURL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(disc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       &rsaKey.PublicKey,
					KeyID:     "test-key-1",
					Algorithm: "RS256",
					Use:       "sig",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	server := httptest.NewServer(mux)
	return server, rsaKey
}

// signIDToken creates a signed JWT with the given claims using the provided RSA key.
func signIDToken(t *testing.T, key *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test-key-1").WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("failed to serialize token: %v", err)
	}

	return compact
}

func TestExchangeCodeForToken_NonceValidation(t *testing.T) {
	oidcServer, rsaKey := testOIDCServer(t)
	defer oidcServer.Close()

	correctNonce := "correct-nonce-value"
	wrongNonce := "wrong-nonce-value"

	// Create an OIDC provider using the test server
	ctx := context.Background()
	oidcProvider, err := oidc.NewProvider(ctx, oidcServer.URL)
	if err != nil {
		t.Fatalf("failed to create oidc provider: %v", err)
	}

	now := time.Now()
	baseClaims := map[string]interface{}{
		"iss":   oidcServer.URL,
		"sub":   "user-123",
		"aud":   "test-client",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nonce": correctNonce,
	}

	t.Run("correct nonce succeeds", func(t *testing.T) {
		idToken := signIDToken(t, rsaKey, baseClaims)

		// Set up token endpoint on the OIDC server
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"access_token":  "test-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "test-refresh-token",
				"id_token":      idToken,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer tokenServer.Close()

		provider := &OIDCProvider{
			Name: "test",
			Config: config.OIDCProvider{
				ClientID: "test-client",
			},
			Provider: oidcProvider,
			OAuth2Config: &oauth2.Config{
				ClientID: "test-client",
				Endpoint: oauth2.Endpoint{
					TokenURL: tokenServer.URL,
				},
			},
			securityConfig: config.SecurityConfig{},
		}

		token, err := provider.ExchangeCodeForToken(ctx, "test-code", correctNonce)
		if err != nil {
			t.Fatalf("expected success with correct nonce, got error: %v", err)
		}
		if token.AccessToken != "test-access-token" {
			t.Errorf("unexpected access token: %s", token.AccessToken)
		}
		if token.Claims["sub"] != "user-123" {
			t.Errorf("unexpected subject claim: %v", token.Claims["sub"])
		}
	})

	t.Run("wrong nonce fails", func(t *testing.T) {
		idToken := signIDToken(t, rsaKey, baseClaims)

		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     idToken,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer tokenServer.Close()

		provider := &OIDCProvider{
			Name: "test",
			Config: config.OIDCProvider{
				ClientID: "test-client",
			},
			Provider: oidcProvider,
			OAuth2Config: &oauth2.Config{
				ClientID: "test-client",
				Endpoint: oauth2.Endpoint{
					TokenURL: tokenServer.URL,
				},
			},
			securityConfig: config.SecurityConfig{},
		}

		_, err := provider.ExchangeCodeForToken(ctx, "test-code", wrongNonce)
		if err == nil {
			t.Fatal("expected error with wrong nonce, got nil")
		}
		if !strings.Contains(err.Error(), "nonce") {
			t.Errorf("error should mention nonce, got: %v", err)
		}
	})
}

func TestExchangeCodeForToken_MissingNonce(t *testing.T) {
	oidcServer, rsaKey := testOIDCServer(t)
	defer oidcServer.Close()

	ctx := context.Background()
	oidcProvider, err := oidc.NewProvider(ctx, oidcServer.URL)
	if err != nil {
		t.Fatalf("failed to create oidc provider: %v", err)
	}

	now := time.Now()
	// ID token with no nonce claim
	claimsWithoutNonce := map[string]interface{}{
		"iss": oidcServer.URL,
		"sub": "user-123",
		"aud": "test-client",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	idToken := signIDToken(t, rsaKey, claimsWithoutNonce)

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	provider := &OIDCProvider{
		Name: "test",
		Config: config.OIDCProvider{
			ClientID: "test-client",
		},
		Provider: oidcProvider,
		OAuth2Config: &oauth2.Config{
			ClientID: "test-client",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenServer.URL,
			},
		},
		securityConfig: config.SecurityConfig{},
	}

	_, err = provider.ExchangeCodeForToken(ctx, "test-code", "expected-nonce")
	if err == nil {
		t.Fatal("expected error when nonce is missing from ID token")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("error should mention nonce, got: %v", err)
	}
}

func TestExchangeCodeForToken_EmptyExpectedNonce(t *testing.T) {
	provider := &OIDCProvider{
		Name: "test",
		Config: config.OIDCProvider{
			ClientID: "test-client",
		},
	}

	_, err := provider.ExchangeCodeForToken(context.Background(), "test-code", "")
	if err == nil {
		t.Fatal("expected error when expected nonce is empty")
	}
	if !strings.Contains(err.Error(), "expected nonce must not be empty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// Ensure go-jose types are used (prevent import pruning)
var _ crypto.Signer = (*rsa.PrivateKey)(nil)
var _ = jose.RS256
var _ = jwt.Claims{}
var _ = big.NewInt
