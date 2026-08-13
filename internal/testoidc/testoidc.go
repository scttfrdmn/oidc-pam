// Package testoidc provides an in-process OpenID Connect issuer for tests.
//
// It speaks enough of OIDC discovery and RFC 8628 (device authorization) for the
// broker to run a whole device flow against it: discovery, JWKS, the device
// authorization endpoint, the token endpoint and userinfo. ID tokens are real
// RS256 JWTs signed with a per-server key and published through the JWKS
// endpoint, so go-oidc's verifier — signature, issuer, audience, expiry and
// nonce — is exercised rather than bypassed.
//
// The point of it is the token endpoint's *sequence* of answers. A real device
// flow answers authorization_pending to every poll until the user finishes in
// the browser, and may answer slow_down; a fake that grants on the first poll
// cannot tell a working client from one that treats pending as fatal, which is
// exactly the bug #150 was. Script() sets that sequence explicitly.
//
// It listens on 127.0.0.1 over plain HTTP, which the broker's endpoint
// validation accepts for localhost only. The containerised end-to-end harness
// needs TLS and a control API on top of this; see test/e2e/fakeoidc.
package testoidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Outcome is one answer from the token endpoint.
type Outcome string

const (
	// Pending is authorization_pending: the user has not finished in the
	// browser yet. Non-terminal — the client must keep polling (RFC 8628 §3.5).
	Pending Outcome = "authorization_pending"
	// SlowDown asks the client to poll less often. Also non-terminal, and the
	// client must add 5 seconds to its interval.
	SlowDown Outcome = "slow_down"
	// Grant issues the tokens: the user approved.
	Grant Outcome = "grant"
	// AccessDenied is terminal: the user (or the IdP) refused.
	AccessDenied Outcome = "access_denied"
	// ExpiredToken is terminal: the device code is no longer valid.
	ExpiredToken Outcome = "expired_token"
)

// Server is a running fake issuer. Create one with New.
type Server struct {
	ts       *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	clientID string

	mu      sync.Mutex
	script  []Outcome
	polls   int
	claims  map[string]any
	devices map[string]string // device_code -> nonce received at the device endpoint
}

// New starts a fake issuer for clientID and registers its shutdown with tb.
// Until Script is called the token endpoint grants on the first poll.
func New(tb testing.TB, clientID string) *Server {
	tb.Helper()

	// 2048 bits: large enough that nothing rejects it, small enough not to
	// dominate the runtime of every test that needs an issuer.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("testoidc: generate signing key: %v", err)
	}

	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		tb.Fatalf("testoidc: marshal public key: %v", err)
	}
	sum := sha256.Sum256(pub)

	s := &Server{
		key:      key,
		kid:      b64(sum[:8]),
		clientID: clientID,
		script:   []Outcome{Grant},
		devices:  make(map[string]string),
		claims: map[string]any{
			"sub":                "test-subject",
			"preferred_username": "testuser",
			"email":              "testuser@example.org",
			"groups":             []string{"researchers"},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/device", s.handleDevice)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/userinfo", s.handleUserInfo)

	s.ts = httptest.NewServer(mux)
	tb.Cleanup(s.ts.Close)
	return s
}

// Issuer is the server's issuer URL, for a provider's `issuer` setting.
func (s *Server) Issuer() string { return s.ts.URL }

// Close shuts the server down. New already registers this with tb.Cleanup;
// call it only to stop the issuer early, e.g. to test a provider going away.
func (s *Server) Close() { s.ts.Close() }

// Script sets the outcomes the token endpoint returns, in order. The last one
// repeats once the script is exhausted, so Script(Pending) answers pending
// forever and Script(Pending, Pending, Grant) grants on the third poll.
func (s *Server) Script(outcomes ...Outcome) {
	if len(outcomes) == 0 {
		panic("testoidc: Script needs at least one outcome")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.script = outcomes
	s.polls = 0
}

// SetClaims replaces the claim set put in ID tokens and returned by userinfo.
// "iss", "aud", "exp", "iat" and "nonce" are always set by the server and
// cannot be overridden here.
func (s *Server) SetClaims(claims map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims = claims
}

// Polls is the number of token-endpoint requests received so far.
func (s *Server) Polls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.polls
}

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.ts.URL,
		"authorization_endpoint":                s.ts.URL + "/authorize",
		"token_endpoint":                        s.ts.URL + "/token",
		"device_authorization_endpoint":         s.ts.URL + "/device",
		"userinfo_endpoint":                     s.ts.URL + "/userinfo",
		"jwks_uri":                              s.ts.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"grant_types_supported": []string{
			"authorization_code",
			"urn:ietf:params:oauth:grant-type:device_code",
		},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": s.kid,
			// RFC 7518 §6.3.1 wants the minimal big-endian encoding of each
			// value, which is what big.Int.Bytes gives.
			"n": b64(s.key.N.Bytes()),
			"e": b64(big.NewInt(int64(s.key.E)).Bytes()),
		}},
	})
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}

	deviceCode := randomString()
	s.mu.Lock()
	// The client sends its nonce here, not at the token endpoint, and expects
	// it echoed in the ID token; remember it per device code.
	s.devices[deviceCode] = r.Form.Get("nonce")
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":      deviceCode,
		"user_code":        "WDJB-MJHT",
		"verification_uri": s.ts.URL + "/activate",
		"expires_in":       600,
		"interval":         5,
	})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	if got := r.Form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:device_code" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "unsupported_grant_type",
			"error_description": fmt.Sprintf("grant_type %q", got),
		})
		return
	}

	s.mu.Lock()
	nonce, known := s.devices[r.Form.Get("device_code")]
	outcome := s.script[min(s.polls, len(s.script)-1)]
	s.polls++
	claims := s.claims
	s.mu.Unlock()

	if !known {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_grant",
			"error_description": "unknown device_code",
		})
		return
	}

	if outcome != Grant {
		// RFC 8628 §3.5: all of these are 400s with an error code; only the
		// code tells a client whether to keep polling.
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": string(outcome)})
		return
	}

	idToken, err := s.signIDToken(claims, nonce)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  "access-" + randomString(),
		"refresh_token": "refresh-" + randomString(),
		"id_token":      idToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
	})
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
		return
	}
	s.mu.Lock()
	claims := s.claims
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, claims)
}

// signIDToken builds an RS256 JWT over claims, with the registered claims the
// verifier checks filled in. Hand-rolled rather than pulled from a JWT library:
// it is three base64 segments and one signature, and it keeps a test-only
// helper from adding a direct dependency.
func (s *Server) signIDToken(claims map[string]any, nonce string) (string, error) {
	payload := make(map[string]any, len(claims)+5)
	for k, v := range claims {
		payload[k] = v
	}
	now := time.Now()
	payload["iss"] = s.ts.URL
	payload["aud"] = s.clientID
	payload["iat"] = now.Unix()
	payload["exp"] = now.Add(time.Hour).Unix()
	if nonce != "" {
		payload["nonce"] = nonce
	}

	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": s.kid})
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal JWT claims: %w", err)
	}

	signingInput := b64(header) + "." + b64(body)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign ID token: %w", err)
	}
	return signingInput + "." + b64(sig), nil
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// randomString returns an unguessable opaque identifier for device codes and
// tokens, so a test cannot accidentally pass by reusing a hardcoded one.
func randomString() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("testoidc: crypto/rand failed: " + err.Error())
	}
	return b64(b)
}
