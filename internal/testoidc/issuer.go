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
	"strings"
	"sync"
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

// Issuer is the behaviour of a fake OpenID Connect provider, without any
// opinion about how it is served. New wraps one in an httptest.Server for
// in-process tests; test/e2e/fakeoidc wraps the same type in a TLS server with a
// control API so the containerised harness drives the identical logic.
//
// Every method is safe for concurrent use: the control API and the broker's poll
// loop touch an Issuer from different goroutines.
type Issuer struct {
	key      *rsa.PrivateKey
	kid      string
	clientID string

	mu          sync.Mutex
	issuerURL   string
	script      []Outcome
	polls       int
	claims      map[string]any
	userInfo    map[string]any    // what /userinfo returns, when it differs; see SetUserInfoClaims
	devices     map[string]string // device_code -> nonce received at the device endpoint
	uriPadBytes int               // extra bytes in verification_uri, see SetVerificationURIPadding
	omitIDToken bool              // grant without an id_token, see SetOmitIDToken
	endpoints   map[string]string // discovery overrides, see SetEndpointOverride
}

// DefaultClaims is the claim set a fresh Issuer puts in ID tokens and returns
// from userinfo. Callers get their own copy and may modify it.
func DefaultClaims() map[string]any {
	return map[string]any{
		"sub":                "test-subject",
		"preferred_username": "testuser",
		"email":              "testuser@example.org",
		"groups":             []string{"researchers"},
	}
}

// NewIssuer creates a fake issuer for clientID. Call SetIssuerURL with the URL
// it will be reachable at before serving Handler: the discovery document and the
// `iss` claim have to name it exactly, or every client rejects the ID token.
//
// Until Script is called the token endpoint grants on the first poll.
func NewIssuer(clientID string) (*Issuer, error) {
	// 2048 bits: large enough that nothing rejects it, small enough not to
	// dominate the runtime of every test that needs an issuer.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(pub)

	return &Issuer{
		key:      key,
		kid:      b64(sum[:8]),
		clientID: clientID,
		script:   []Outcome{Grant},
		claims:   DefaultClaims(),
		devices:  make(map[string]string),
	}, nil
}

// SetIssuerURL sets the URL the issuer claims to live at.
func (i *Issuer) SetIssuerURL(url string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.issuerURL = strings.TrimSuffix(url, "/")
}

// IssuerURL is the URL the issuer claims to live at.
func (i *Issuer) IssuerURL() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.issuerURL
}

// Script sets the outcomes the token endpoint returns, in order. The last one
// repeats once the script is exhausted, so Script(Pending) answers pending
// forever and Script(Pending, Pending, Grant) grants on the third poll.
//
// It does not reset the poll count: a harness that waits for the client to poll
// and only then approves needs both facts to survive the change.
func (i *Issuer) Script(outcomes ...Outcome) {
	if len(outcomes) == 0 {
		panic("testoidc: Script needs at least one outcome")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.script = outcomes
}

// SetClaims replaces the claim set put in ID tokens and returned by userinfo.
// "iss", "aud", "exp", "iat" and "nonce" are always set by the issuer and
// cannot be overridden here.
func (i *Issuer) SetClaims(claims map[string]any) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.claims = claims
}

// Claims is the claim set currently in use.
func (i *Issuer) Claims() map[string]any {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.claims
}

// SetUserInfoClaims makes /userinfo answer with its own claim set instead of the
// one the ID token carries, so the two can disagree.
//
// Real providers differ between the two endpoints all the time — different scopes
// are reflected in each, and some claims are only ever returned by /userinfo — and
// an issuer whose two answers are identical cannot show which of them a client
// believes. That is what #167 was: /userinfo took precedence, so the value that
// authorized the login came from an unsigned JSON body even when a signed ID token
// said something else. Pass nil to go back to serving the ID token's claims.
func (i *Issuer) SetUserInfoClaims(claims map[string]any) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.userInfo = claims
}

// SetOmitIDToken makes a granting token response leave out id_token, as a provider
// that does not implement OIDC on the device grant does. Everything a client can
// verify is in that token, so an identity built from such a response is asserted by
// nothing but TLS and the bearer token (#167).
func (i *Issuer) SetOmitIDToken(omit bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.omitIDToken = omit
}

// SetEndpointOverride makes the discovery document advertise url for the named
// endpoint ("token_endpoint", "userinfo_endpoint", ...) instead of this issuer's
// own. An empty url drops the key from the document entirely.
//
// Both a legitimate and a hostile provider do this: Google's token endpoint is on
// a different host from its issuer, while a tampered discovery response naming
// http:// is how a client ends up posting an access token in cleartext (#167).
func (i *Issuer) SetEndpointOverride(name, url string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.endpoints == nil {
		i.endpoints = make(map[string]string)
	}
	i.endpoints[name] = url
}

// Polls is the number of token-endpoint requests received since the issuer was
// created or last Reset.
func (i *Issuer) Polls() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.polls
}

// NextOutcome is the answer the next poll will get, which is what a harness
// reports as the issuer's state.
func (i *Issuer) NextOutcome() Outcome {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.script[min(i.polls, len(i.script)-1)]
}

// SetVerificationURIPadding makes the device endpoint return a verification_uri
// padded with n extra bytes of query string.
//
// Real providers hand out short URIs, which is why nothing caught #162: the
// verification URI reaches the PAM module three times over — as device_url, as
// text in the instructions, and as QR art that grows with it — and a URI of a few
// hundred bytes was enough to push the response past the module's response buffer.
// A harness that only ever sees a 29-byte URI cannot tell that this is broken.
func (i *Issuer) SetVerificationURIPadding(n int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.uriPadBytes = n
}

// VerificationURIPadding is the padding currently in effect, so a harness can
// report it as part of the issuer's state.
func (i *Issuer) VerificationURIPadding() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.uriPadBytes
}

// Reset returns the issuer to its initial state: default claims, no polls
// recorded, no device codes outstanding, and an unpadded verification URI. The
// script is left alone, since a harness sets it per case.
func (i *Issuer) Reset() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.polls = 0
	i.claims = DefaultClaims()
	i.userInfo = nil
	i.devices = make(map[string]string)
	i.uriPadBytes = 0
	i.omitIDToken = false
	i.endpoints = nil
}

// Handler serves the OIDC endpoints. The paths are also what the discovery
// document advertises, so a client that follows discovery needs to know none of
// them.
func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", i.handleDiscovery)
	mux.HandleFunc("/jwks", i.handleJWKS)
	mux.HandleFunc("/device", i.handleDevice)
	mux.HandleFunc("/token", i.handleToken)
	mux.HandleFunc("/userinfo", i.handleUserInfo)
	return mux
}

func (i *Issuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	base := i.issuerURL
	overrides := make(map[string]string, len(i.endpoints))
	for name, url := range i.endpoints {
		overrides[name] = url
	}
	i.mu.Unlock()

	doc := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"device_authorization_endpoint":         base + "/device",
		"userinfo_endpoint":                     base + "/userinfo",
		"jwks_uri":                              base + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"grant_types_supported": []string{
			"authorization_code",
			"urn:ietf:params:oauth:grant-type:device_code",
		},
	}
	for name, url := range overrides {
		if url == "" {
			delete(doc, name)
			continue
		}
		doc[name] = url
	}
	writeJSON(w, http.StatusOK, doc)
}

func (i *Issuer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": i.kid,
			// RFC 7518 §6.3.1 wants the minimal big-endian encoding of each
			// value, which is what big.Int.Bytes gives.
			"n": b64(i.key.N.Bytes()),
			"e": b64(big.NewInt(int64(i.key.E)).Bytes()),
		}},
	})
}

func (i *Issuer) handleDevice(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}

	if !i.checkClient(w, r) {
		return
	}

	deviceCode := randomString()
	i.mu.Lock()
	// The client sends its nonce here, not at the token endpoint, and expects
	// it echoed in the ID token; remember it per device code.
	i.devices[deviceCode] = r.Form.Get("nonce")
	base := i.issuerURL
	pad := i.uriPadBytes
	i.mu.Unlock()

	verificationURI := base + "/activate"
	if pad > 0 {
		verificationURI += "?p=" + strings.Repeat("p", pad)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":      deviceCode,
		"user_code":        "WDJB-MJHT",
		"verification_uri": verificationURI,
		"expires_in":       600,
		"interval":         5,
	})
}

func (i *Issuer) handleToken(w http.ResponseWriter, r *http.Request) {
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
	if !i.checkClient(w, r) {
		return
	}

	i.mu.Lock()
	nonce, known := i.devices[r.Form.Get("device_code")]
	outcome := i.script[min(i.polls, len(i.script)-1)]
	i.polls++
	claims := i.claims
	omitIDToken := i.omitIDToken
	i.mu.Unlock()

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

	grant := map[string]any{
		"access_token":  "access-" + randomString(),
		"refresh_token": "refresh-" + randomString(),
		"token_type":    "Bearer",
		"expires_in":    3600,
	}
	if !omitIDToken {
		idToken, err := i.signIDToken(claims, nonce)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
			return
		}
		grant["id_token"] = idToken
	}
	writeJSON(w, http.StatusOK, grant)
}

// checkClient rejects a request that does not identify itself as the client this
// issuer was created for. RFC 8628 device flow is a public-client grant, so
// client_id is the whole of the client's identity — a broker that omitted it, or
// sent someone else's, must fail here rather than quietly get tokens.
func (i *Issuer) checkClient(w http.ResponseWriter, r *http.Request) bool {
	if got := r.Form.Get("client_id"); got != i.clientID {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_client",
			"error_description": fmt.Sprintf("client_id %q", got),
		})
		return false
	}
	return true
}

func (i *Issuer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
		return
	}
	i.mu.Lock()
	claims := i.userInfo
	if claims == nil {
		claims = i.claims
	}
	i.mu.Unlock()
	writeJSON(w, http.StatusOK, claims)
}

// signIDToken builds an RS256 JWT over claims, with the registered claims the
// verifier checks filled in. Hand-rolled rather than pulled from a JWT library:
// it is three base64 segments and one signature, and it keeps a test-only
// helper from adding a direct dependency.
func (i *Issuer) signIDToken(claims map[string]any, nonce string) (string, error) {
	payload := make(map[string]any, len(claims)+5)
	for k, v := range claims {
		payload[k] = v
	}
	now := time.Now()
	payload["iss"] = i.IssuerURL()
	payload["aud"] = i.clientID
	payload["iat"] = now.Unix()
	payload["exp"] = now.Add(time.Hour).Unix()
	if nonce != "" {
		payload["nonce"] = nonce
	}

	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": i.kid})
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal JWT claims: %w", err)
	}

	signingInput := b64(header) + "." + b64(body)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
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
