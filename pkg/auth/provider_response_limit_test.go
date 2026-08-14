package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/internal/testoidc"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"golang.org/x/oauth2"
)

// #223: every JSON body the broker reads from a provider used to be decoded
// straight from resp.Body, so the size of the allocation was the provider's
// choice. "The provider" is whatever answers as one — an attacker-run host
// reached through a stolen `issuer`, a DNS or TLS trust compromise — and the
// broker is a root process the host's logins all depend on, with no MemoryMax in
// the shipped unit. These tests drive each of the five bodies from a stub that
// answers one byte over the limit.

// providerJSON returns a JSON object of exactly total bytes carrying fields,
// grown to size with a member none of the response types read. A body built this
// way still decodes normally, so a test that expects it to be refused is
// asserting on the size limit and nothing else.
func providerJSON(t *testing.T, fields map[string]any, total int) []byte {
	t.Helper()

	padded := make(map[string]any, len(fields)+1)
	for k, v := range fields {
		padded[k] = v
	}
	padded["padding"] = ""

	empty, err := json.Marshal(padded)
	if err != nil {
		t.Fatalf("marshalling the stub body: %v", err)
	}
	if len(empty) > total {
		t.Fatalf("the fields alone are %d bytes, over the %d asked for", len(empty), total)
	}

	// "p" is a byte JSON never escapes, so the padding costs exactly its length.
	padded["padding"] = strings.Repeat("p", total-len(empty))
	body, err := json.Marshal(padded)
	if err != nil {
		t.Fatalf("marshalling the padded stub body: %v", err)
	}
	if len(body) != total {
		t.Fatalf("stub body is %d bytes, want exactly %d", len(body), total)
	}
	return body
}

// providerServing is a stub provider answering every request with body.
func providerServing(t *testing.T, body []byte) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

// providerAt builds a provider that talks to a stub server as its whole world:
// issuer, device endpoint and HTTP client.
func providerAt(server *httptest.Server) *OIDCProvider {
	return &OIDCProvider{
		Name: "test-provider",
		Config: config.OIDCProvider{
			Name:           "test-provider",
			Issuer:         server.URL,
			ClientID:       "test-client",
			Scopes:         []string{"openid"},
			DeviceEndpoint: server.URL + "/device",
		},
		httpClient: server.Client(),
	}
}

func TestProviderResponsesOverTheLimitAreRefused(t *testing.T) {
	oversized := maxProviderResponseBytes + 1

	for _, tc := range []struct {
		name string
		// body is what the stub answers with, once the test knows how large that
		// has to be.
		body func(t *testing.T) []byte
		// call makes the request that reads it.
		call func(t *testing.T, server *httptest.Server) error
	}{
		{
			name: "device authorization response",
			body: func(t *testing.T) []byte {
				return providerJSON(t, map[string]any{
					"device_code":      "device-code",
					"user_code":        "WDJB-MJHT",
					"verification_uri": "https://idp.example.com/device",
					"expires_in":       600,
					"interval":         5,
				}, oversized)
			},
			call: func(t *testing.T, server *httptest.Server) error {
				_, err := providerAt(server).StartDeviceFlow(&AuthRequest{UserID: "testuser", LoginType: "ssh"})
				return err
			},
		},
		{
			name: "token response",
			body: func(t *testing.T) []byte {
				return providerJSON(t, map[string]any{
					"access_token": "at",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}, oversized)
			},
			call: func(t *testing.T, server *httptest.Server) error {
				// The token endpoint is read out of discovery, so an issuer that
				// advertises the stub is how a real provider points the poll at it.
				provider := providerWithEndpointAt(t, "token_endpoint", server.URL)
				_, err := provider.PollDeviceAuthorization(context.Background(), "device-code", "nonce")
				return err
			},
		},
		{
			name: "token refresh response",
			body: func(t *testing.T) []byte {
				return providerJSON(t, map[string]any{
					"access_token": "at",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}, oversized)
			},
			call: func(t *testing.T, server *httptest.Server) error {
				provider := providerAt(server)
				provider.OAuth2Config = &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: server.URL + "/token"}}
				_, err := provider.RefreshToken(context.Background(), "refresh-token")
				return err
			},
		},
		{
			name: "userinfo response",
			body: func(t *testing.T) []byte {
				return providerJSON(t, map[string]any{"sub": "user-1"}, oversized)
			},
			call: func(t *testing.T, server *httptest.Server) error {
				provider := providerWithEndpointAt(t, "userinfo_endpoint", server.URL)
				_, err := provider.GetUserInfo(&Token{AccessToken: "at"})
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := providerServing(t, tc.body(t))

			err := tc.call(t, server)
			if err == nil {
				t.Fatalf("a %d-byte %s was accepted; the broker allocates whatever the "+
					"provider sends (#223)", oversized, tc.name)
			}
			if !strings.Contains(err.Error(), "over the") || !strings.Contains(err.Error(), "limit") {
				t.Errorf("error does not say the body was over the limit, so an operator cannot "+
					"tell this from a malformed response: %v", err)
			}
		})
	}
}

// providerWithEndpointAt is a provider whose discovery document advertises url
// for one endpoint, so a call that reads that endpoint from discovery — the poll
// and userinfo paths both do — reaches the stub.
func providerWithEndpointAt(t *testing.T, endpoint, url string) *OIDCProvider {
	t.Helper()

	const clientID = "oidc-pam-test-client"
	idp := testoidc.New(t, clientID)
	idp.SetEndpointOverride(endpoint, url)

	provider, err := NewOIDCProvider(config.OIDCProvider{
		Name:            "testidp",
		Issuer:          idp.Issuer(),
		ClientID:        clientID,
		Scopes:          []string{"openid"},
		EnabledForLogin: true,
		UserMapping:     config.UserMapping{UsernameClaim: "preferred_username"},
	}, config.SecurityConfig{
		TokenEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider against the in-process issuer: %v", err)
	}
	return provider
}

// A discovery document over the limit is not a fatal error — the endpoint it
// would have named is guessed instead — but it must not be read. The stub's
// document advertises a device endpoint that passes every other check, so the
// endpoint the broker comes back with says whether it decoded the body.
func TestOversizedDiscoveryDocumentIsNotRead(t *testing.T) {
	// The advertised endpoint has to be on the issuer's own host to survive
	// validateEndpoint, so the body cannot be built until the stub's address is
	// known. An unstarted server has a listener, and therefore an address, before
	// it serves anything.
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	addr := "http://" + server.Listener.Addr().String()

	body := providerJSON(t, map[string]any{
		"device_authorization_endpoint": addr + "/discovered-device",
	}, maxProviderResponseBytes+1)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	server.Start()

	provider := providerAt(server)
	provider.Config.DeviceEndpoint = "" // force discovery

	endpoint, err := provider.getDeviceAuthorizationEndpoint()
	if err != nil {
		t.Fatalf("getDeviceAuthorizationEndpoint: %v", err)
	}
	if endpoint == server.URL+"/discovered-device" {
		t.Fatalf("the broker used an endpoint out of a %d-byte discovery document, so it decoded "+
			"the whole of it (#223)", maxProviderResponseBytes+1)
	}
	if want := server.URL + "/protocol/openid-connect/auth/device"; endpoint != want {
		t.Errorf("endpoint = %q, want the guessed fallback %q", endpoint, want)
	}
}

// The limit is inclusive: a body of exactly maxProviderResponseBytes is a body
// the broker reads. A bound that rejects the size it documents turns a legitimate
// provider's largest response into a login failure nobody can explain.
func TestProviderResponseExactlyAtTheLimitIsAccepted(t *testing.T) {
	body := providerJSON(t, map[string]any{
		"device_code":      "device-code",
		"user_code":        "WDJB-MJHT",
		"verification_uri": "https://idp.example.com/device",
		"expires_in":       600,
		"interval":         5,
	}, maxProviderResponseBytes)

	flow, err := providerAt(providerServing(t, body)).StartDeviceFlow(&AuthRequest{
		UserID:    "testuser",
		LoginType: "ssh",
	})
	if err != nil {
		t.Fatalf("a body of exactly the %d-byte limit was refused: %v", maxProviderResponseBytes, err)
	}
	if flow.DeviceCode != "device-code" {
		t.Errorf("device code = %q, want the one the provider sent", flow.DeviceCode)
	}
	if flow.ExpiresAt.Before(time.Now()) {
		t.Error("the flow is already expired, so the body was not decoded as sent")
	}
}
