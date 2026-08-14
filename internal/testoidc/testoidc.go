// Package testoidc provides a fake OpenID Connect issuer for tests.
//
// It speaks enough of OIDC discovery and RFC 8628 (device authorization) for the
// broker to run a whole device flow against it: discovery, JWKS, the device
// authorization endpoint, the token endpoint and userinfo. ID tokens are real
// RS256 JWTs signed with a per-issuer key and published through the JWKS
// endpoint, so go-oidc's verifier — signature, issuer, audience, expiry and
// nonce — is exercised rather than bypassed.
//
// The point of it is the token endpoint's *sequence* of answers. A real device
// flow answers authorization_pending to every poll until the user finishes in
// the browser, and may answer slow_down; a fake that grants on the first poll
// cannot tell a working client from one that treats pending as fatal, which is
// exactly the bug #150 was. Script() sets that sequence explicitly.
//
// Issuer holds all of that behaviour and knows nothing about how it is served.
// New wraps one in an httptest.Server on 127.0.0.1 over plain HTTP, which the
// broker's endpoint validation accepts for localhost only; test/e2e/fakeoidc
// wraps the same Issuer in a TLS server with a control API, so the containerised
// harness and the in-process tests drive identical logic.
package testoidc

import (
	"net/http/httptest"
	"testing"
)

// Server is a fake issuer running on a local HTTP listener. Create one with New.
type Server struct {
	iss *Issuer
	ts  *httptest.Server
}

// New starts a fake issuer for clientID and registers its shutdown with tb.
// Until Script is called the token endpoint grants on the first poll.
func New(tb testing.TB, clientID string) *Server {
	tb.Helper()

	iss, err := NewIssuer(clientID)
	if err != nil {
		tb.Fatalf("testoidc: %v", err)
	}

	ts := httptest.NewServer(iss.Handler())
	// Only now is the URL known, and discovery has to advertise it.
	iss.SetIssuerURL(ts.URL)

	tb.Cleanup(ts.Close)
	return &Server{iss: iss, ts: ts}
}

// Issuer is the server's issuer URL, for a provider's `issuer` setting.
func (s *Server) Issuer() string { return s.ts.URL }

// Close shuts the server down. New already registers this with tb.Cleanup;
// call it only to stop the issuer early, e.g. to test a provider going away.
func (s *Server) Close() { s.ts.Close() }

// Script sets the outcomes the token endpoint returns, in order. See
// Issuer.Script.
func (s *Server) Script(outcomes ...Outcome) { s.iss.Script(outcomes...) }

// SetClaims replaces the claim set put in ID tokens and returned by userinfo.
// See Issuer.SetClaims.
func (s *Server) SetClaims(claims map[string]any) { s.iss.SetClaims(claims) }

// SetUserInfoClaims makes /userinfo answer with its own claim set, so it can
// disagree with the ID token. See Issuer.SetUserInfoClaims.
func (s *Server) SetUserInfoClaims(claims map[string]any) { s.iss.SetUserInfoClaims(claims) }

// SetOmitIDToken makes a granting token response leave out id_token. See
// Issuer.SetOmitIDToken.
func (s *Server) SetOmitIDToken(omit bool) { s.iss.SetOmitIDToken(omit) }

// SetEndpointOverride changes what the discovery document advertises for one
// endpoint. See Issuer.SetEndpointOverride.
func (s *Server) SetEndpointOverride(name, url string) { s.iss.SetEndpointOverride(name, url) }

// Polls is the number of token-endpoint requests received so far.
func (s *Server) Polls() int { return s.iss.Polls() }
