package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/oidc-pam/internal/testoidc"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// These tests are about how much the broker takes the provider's word for (#167).
// Each one runs through Broker.pollDeviceAuthorization against the in-process
// issuer, or through NewOIDCProvider against its discovery document, because all
// three defects were in what the *real* path accepts rather than in any single
// function's logic: the verification block was skipped for want of an ID token, the
// merge that decided which claim authorizes a login preferred the unsigned one, and
// two of the three endpoints were never checked before credentials went to them.

// requireIDToken is the pointer form of the per-provider flag, so a test can say
// which of the two states it means rather than relying on the zero value.
func requireIDToken(v bool) *bool { return &v }

// A granting token response with no id_token is refused under the default.
//
// The ID token is the only verifiable part of that response: signature, issuer,
// audience, expiry and the nonce the broker sent are all in it, and every one of
// those checks sat behind `if tokenResp.IDToken != ""`. A provider that simply
// omitted the field therefore produced a session whose identity came from
// /userinfo — a JSON body vouched for by nothing but TLS and the bearer token —
// with no audience check at all, so a token minted for a different client would
// have been accepted.
func TestGrantWithoutAnIDTokenIsRefused(t *testing.T) {
	env := newPollTestEnv(t)
	env.idp.SetOmitIDToken(true)
	env.idp.Script(testoidc.Grant)

	env.run(t)

	if session := env.activeSession(); session != nil {
		t.Errorf("a session was activated from a token response with no id_token, so nothing about "+
			"this authorization was verified (#167): %+v", session)
	}

	event := env.auditEvent(t, "device_authorization_failed")
	if event.ErrorCode != "ID_TOKEN_MISSING" {
		t.Errorf("refusal recorded with error_code %q, want ID_TOKEN_MISSING (nothing was wrong with "+
			"an ID token; there was none)", event.ErrorCode)
	}
	if !strings.Contains(event.ErrorMessage, "require_id_token") {
		t.Errorf("the audited refusal does not name the key that would permit this provider: %q",
			event.ErrorMessage)
	}
	for _, e := range env.auditEvents(t) {
		if e.EventType == "authentication_successful" {
			t.Fatal("an unverifiable authorization was recorded as a successful login (#167)")
		}
	}

	// And no credential was minted for it.
	if _, err := env.broker.keyManager.LoadKey(env.session.ID); err == nil {
		t.Error("a refused login left a key pair in the key store")
	}
	authorizedKeys := filepath.Join(env.homeDir, env.session.UserID, ".ssh", "authorized_keys")
	if data, err := os.ReadFile(authorizedKeys); err == nil && strings.Contains(string(data), "@oidc-pam-") {
		t.Errorf("a refused login installed a login key:\n%s", data)
	}
}

// The deployment the default must not strand: an operator whose provider does not
// issue ID tokens for the device grant sets require_id_token: false and the same
// flow completes, on an identity from /userinfo. The escape hatch has to work, or
// the default is not a choice.
func TestRequireIDTokenFalseAcceptsAUserInfoOnlyIdentity(t *testing.T) {
	env := newPollTestEnv(t)
	env.provider.Config.RequireIDToken = requireIDToken(false)
	env.idp.SetOmitIDToken(true)
	env.idp.Script(testoidc.Grant)

	env.run(t)

	session := env.activeSession()
	if session == nil || !session.IsActive {
		t.Fatal("require_id_token: false did not permit a grant without an id_token")
	}
	if session.Email != "testuser@example.org" {
		t.Errorf("session email = %q, want the value /userinfo returned — with no ID token that is "+
			"the only source of claims", session.Email)
	}
}

// The unset key means required, in a config built in Go as well as in loaded YAML.
// This is the fail-closed direction and the state every existing deployment is in,
// so it is pinned explicitly rather than inferred from the test above.
func TestIDTokenRequiredDefaultsToOn(t *testing.T) {
	if !(config.OIDCProvider{}).IDTokenRequired() {
		t.Error("a provider that never mentions require_id_token does not require an ID token")
	}
	if (config.OIDCProvider{RequireIDToken: requireIDToken(false)}).IDTokenRequired() {
		t.Error("require_id_token: false still requires an ID token")
	}
	if !(config.OIDCProvider{RequireIDToken: requireIDToken(true)}).IDTokenRequired() {
		t.Error("require_id_token: true does not require an ID token")
	}
}

// Where the ID token and /userinfo disagree, the signed one decides.
//
// The merge used to fill gaps in one direction only, with /userinfo winning, so the
// claim that authorizes the login could come from an unsigned JSON body even when a
// verified ID token said otherwise. The two halves are the two directions that
// matters in: the signed value must be the one that binds, and the unsigned one
// must not be able to authorize a login the signature does not support.
func TestIDTokenClaimsWinOverUserInfo(t *testing.T) {
	t.Run("the signed claim is the one that binds", func(t *testing.T) {
		env := newPollTestEnv(t)
		// No groups in the ID token, so the gap-filling half of the merge is
		// exercised at the same time: a claim only /userinfo carries still arrives.
		env.idp.SetClaims(map[string]any{
			"sub":                "test-subject",
			"preferred_username": "testuser",
			"email":              "testuser@example.org",
		})
		env.idp.SetUserInfoClaims(map[string]any{
			"sub":                "test-subject",
			"preferred_username": "someone-else",
			"email":              "someone-else@example.org",
			"groups":             []string{"researchers"},
		})
		env.idp.Script(testoidc.Grant)

		env.run(t)

		session := env.activeSession()
		if session == nil || !session.IsActive {
			t.Fatal("a login whose ID token names the requested account was refused")
		}
		if session.Email != "testuser@example.org" {
			t.Errorf("session email = %q, want the ID token's value: where the two sources disagree "+
				"the signed one wins (#167)", session.Email)
		}
		if len(session.Groups) != 1 || session.Groups[0] != "researchers" {
			t.Errorf("session groups = %v, want [researchers]: a claim only /userinfo returns is still "+
				"used, since the ID token has nothing to say about it", session.Groups)
		}
	})

	t.Run("an unsigned claim cannot authorize what the ID token does not", func(t *testing.T) {
		env := newPollTestEnv(t)
		// The signed assertion is for someone else entirely; /userinfo names the
		// local account being logged into. On the old merge /userinfo won, the
		// binding compared "testuser" against "testuser" and the login was
		// approved on the strength of an unsigned response body.
		env.idp.SetClaims(map[string]any{
			"sub":                "sub-someone-else",
			"preferred_username": "someone-else",
			"email":              "someone-else@example.org",
			"groups":             []string{"researchers"},
		})
		env.idp.SetUserInfoClaims(map[string]any{
			"sub":                "sub-someone-else",
			"preferred_username": "testuser",
			"email":              "testuser@example.org",
			"groups":             []string{"researchers"},
		})
		env.idp.Script(testoidc.Grant)

		env.run(t)

		if session := env.activeSession(); session != nil {
			t.Errorf("a login was authorized for %q on a /userinfo claim that the signed ID token "+
				"contradicts (#167): %+v", env.session.UserID, session)
		}
		event := env.auditEvent(t, "authentication_denied")
		if event.ErrorCode != "IDENTITY_MISMATCH" {
			t.Errorf("denial recorded with error_code %q, want IDENTITY_MISMATCH", event.ErrorCode)
		}
		for _, e := range env.auditEvents(t) {
			if e.EventType == "authentication_successful" {
				t.Fatal("a login authorized by /userinfo against the ID token was recorded as successful (#167)")
			}
		}
	})
}

// Every endpoint the broker will send credentials to has to be over TLS, and it is
// the discovery document that names them.
//
// validateEndpoint was applied to the device authorization endpoint alone; the token
// and userinfo endpoints were taken from discovery unchecked. A discovery response
// naming http:// therefore had the broker post the device code to, and carry the
// access token to, a plaintext endpoint — with the CA bundle, the skip-verify flag
// and the certificate pins all bypassed, because none of them apply to a connection
// that never negotiates TLS.
//
// The check is at load, so a provider like this stops the broker starting instead of
// failing one login at a time. Note the last case: only the scheme is enforced, not
// an issuer-host match, because a token endpoint on another host is ordinary — it is
// where Google's and Cognito's live.
func TestDiscoveredEndpointsMustUseTLS(t *testing.T) {
	const clientID = "oidc-pam-test-client"

	tests := []struct {
		name         string
		endpoint     string
		url          string
		wantRejected bool
	}{
		{
			name:         "token endpoint downgraded to http",
			endpoint:     "token_endpoint",
			url:          "http://token.idp.example.net/token",
			wantRejected: true,
		},
		{
			name:         "userinfo endpoint downgraded to http",
			endpoint:     "userinfo_endpoint",
			url:          "http://idp.example.net/userinfo",
			wantRejected: true,
		},
		{
			name:         "device authorization endpoint downgraded to http",
			endpoint:     "device_authorization_endpoint",
			url:          "http://idp.example.net/device",
			wantRejected: true,
		},
		{
			// The "localhost.attacker.example" shape: a prefix match on the host
			// would have taken this for loopback and allowed plaintext.
			name:         "a hostname that merely starts with localhost is not loopback",
			endpoint:     "token_endpoint",
			url:          "http://localhost.idp.example.net/token",
			wantRejected: true,
		},
		{
			name:     "a token endpoint on another host over https is accepted",
			endpoint: "token_endpoint",
			url:      "https://oauth2.idp.example.net/token",
		},
		{
			name:     "the issuer's own endpoints are accepted",
			endpoint: "token_endpoint",
			url:      "", // no override
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := testoidc.New(t, clientID)
			if tc.url != "" {
				idp.SetEndpointOverride(tc.endpoint, tc.url)
			}

			_, err := NewOIDCProvider(config.OIDCProvider{
				Name:            "testidp",
				Issuer:          idp.Issuer(),
				ClientID:        clientID,
				Scopes:          []string{"openid", "profile", "email"},
				EnabledForLogin: true,
			}, config.SecurityConfig{VerifyAudience: true})

			if !tc.wantRejected {
				if err != nil {
					t.Fatalf("NewOIDCProvider rejected a provider it should accept: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("NewOIDCProvider accepted a discovery document naming %s: %s — the broker "+
					"would send credentials to it in cleartext (#167)", tc.endpoint, tc.url)
			}
			if !strings.Contains(err.Error(), tc.endpoint) {
				t.Errorf("the error does not name the endpoint that was rejected: %v", err)
			}
		})
	}
}

// The configured form of the same thing: under skip_discovery the endpoints come
// from the config file rather than from discovery, and they are checked on the same
// path.
func TestConfiguredEndpointsMustUseTLSUnderSkipDiscovery(t *testing.T) {
	base := config.OIDCProvider{
		Name:            "no-discovery-idp",
		Issuer:          "https://idp.example.net",
		ClientID:        "test-client",
		Scopes:          []string{"openid"},
		SkipDiscovery:   true,
		JWKSUri:         "https://idp.example.net/jwks",
		TokenEndpoint:   "https://idp.example.net/token",
		EnabledForLogin: true,
	}

	if _, err := NewOIDCProvider(base, config.SecurityConfig{VerifyAudience: true}); err != nil {
		t.Fatalf("an all-HTTPS skip_discovery provider was rejected: %v", err)
	}

	downgraded := base
	downgraded.UserInfoEndpoint = "http://idp.example.net/userinfo"
	if _, err := NewOIDCProvider(downgraded, config.SecurityConfig{VerifyAudience: true}); err == nil {
		t.Error("a skip_discovery provider with a plaintext userinfo_endpoint was accepted")
	}
}
