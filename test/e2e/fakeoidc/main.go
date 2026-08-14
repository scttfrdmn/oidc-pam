// Command fakeoidc is the identity provider the end-to-end harness runs
// against: internal/testoidc's Issuer, served over TLS, with a control API the
// test cases drive with curl.
//
// Two listeners, deliberately:
//
//   - The OIDC endpoints are HTTPS, because the broker refuses a non-https
//     issuer for anything but localhost, and refuses an endpoint whose host
//     differs from the issuer's. A container-to-container fake therefore has to
//     present a certificate the broker trusts (Dockerfile.broker generates one
//     and points the broker's trusted_ca_bundle at it).
//   - The control API is plain HTTP on a separate port, so nothing about the
//     harness's own plumbing can be mistaken for the identity provider. It is
//     never reachable by the broker's OIDC client.
//
// The device flow it serves is hermetic: no browser is involved, and a case
// decides exactly when — and whether — the "user" approves, which is what makes
// "the login must keep waiting" and "the login must be refused" testable at all.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/scttfrdmn/oidc-pam/internal/testoidc"
)

func main() {
	var (
		clientID      = flag.String("client-id", "oidc-pam-e2e", "client_id this issuer accepts")
		issuerURL     = flag.String("issuer", "https://fakeoidc:8443", "issuer URL, as the broker is configured with it")
		oidcAddr      = flag.String("oidc-listen", ":8443", "address for the HTTPS OIDC endpoints")
		controlAddr   = flag.String("control-listen", ":8080", "address for the plain-HTTP control API")
		certFile      = flag.String("cert", "/etc/fakeoidc/tls.crt", "TLS certificate for the OIDC listener")
		keyFile       = flag.String("key", "/etc/fakeoidc/tls.key", "TLS private key for the OIDC listener")
		initialScript = flag.String("initial-outcome", string(testoidc.Pending),
			"what the token endpoint answers until a control request changes it")
	)
	flag.Parse()

	iss, err := testoidc.NewIssuer(*clientID)
	if err != nil {
		log.Fatalf("fakeoidc: %v", err)
	}
	iss.SetIssuerURL(*issuerURL)
	// Nothing is approved until a case says so: an issuer that granted on the
	// first poll would let a broken client pass every scenario.
	iss.Script(testoidc.Outcome(*initialScript))

	control := &http.Server{
		Addr:              *controlAddr,
		Handler:           controlHandler(iss),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("fakeoidc: control API on %s", *controlAddr)
		if err := control.ListenAndServe(); err != nil {
			log.Fatalf("fakeoidc: control listener: %v", err)
		}
	}()

	oidcSrv := &http.Server{
		Addr:              *oidcAddr,
		Handler:           logRequests(iss.Handler()),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("fakeoidc: issuer %s on %s", *issuerURL, *oidcAddr)
	if err := oidcSrv.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		log.Printf("fakeoidc: OIDC listener: %v", err)
		os.Exit(1)
	}
}

// controlHandler is the harness's remote control. Every route is a GET so a case
// is one curl, and each returns the resulting state so a case can assert on it
// without a second request.
func controlHandler(iss *testoidc.Issuer) http.Handler {
	mux := http.NewServeMux()

	// Approve: the "user" finished in the browser. The next poll gets tokens.
	mux.HandleFunc("/control/approve", func(w http.ResponseWriter, r *http.Request) {
		iss.Script(testoidc.Grant)
		writeState(w, iss, "approved")
	})

	// Deny: the "user" refused. Terminal — the broker must stop polling.
	mux.HandleFunc("/control/deny", func(w http.ResponseWriter, r *http.Request) {
		iss.Script(testoidc.AccessDenied)
		writeState(w, iss, "denied")
	})

	// Expire: the device code is no longer valid. Also terminal.
	mux.HandleFunc("/control/expire", func(w http.ResponseWriter, r *http.Request) {
		iss.Script(testoidc.ExpiredToken)
		writeState(w, iss, "expired")
	})

	// Pending: answer authorization_pending to every poll, forever. This is the
	// state a case starts in, and what "the user has not got round to it yet"
	// looks like on the wire.
	mux.HandleFunc("/control/pending", func(w http.ResponseWriter, r *http.Request) {
		iss.Script(testoidc.Pending)
		writeState(w, iss, "pending")
	})

	// Identity: who the ID token says the user is. This is how a case makes
	// preferred_username disagree with the local account the login is for, or
	// drops the group the broker requires.
	//
	//   /control/identity?username=carol
	//   /control/identity?username=alice&groups=
	//   /control/identity?username=alice&groups=researchers,staff
	mux.HandleFunc("/control/identity", func(w http.ResponseWriter, r *http.Request) {
		claims := testoidc.DefaultClaims()
		q := r.URL.Query()
		if username := q.Get("username"); username != "" {
			claims["preferred_username"] = username
			claims["sub"] = "sub-" + username
			claims["email"] = username + "@example.org"
		}
		if q.Has("groups") {
			claims["groups"] = splitGroups(q.Get("groups"))
		}
		iss.SetClaims(claims)
		writeState(w, iss, "identity set")
	})

	// Verification URI: how long a verification_uri the provider hands out.
	//
	//   /control/verification-uri?pad=400
	//   /control/verification-uri?pad=0
	//
	// A real provider's URI is short, which is why nothing in this harness caught
	// #162 — the URI reaches the PAM module three times over (as device_url, as text
	// in the instructions, and as QR art that grows with it), so a few hundred bytes
	// of it used to overflow the module's response buffer and refuse every login on
	// the host. Padding is how a case asks for a URI long enough to prove that the
	// login still works.
	mux.HandleFunc("/control/verification-uri", func(w http.ResponseWriter, r *http.Request) {
		pad, err := strconv.Atoi(r.URL.Query().Get("pad"))
		if err != nil || pad < 0 {
			http.Error(w, "pad must be a non-negative number of bytes\n", http.StatusBadRequest)
			return
		}
		iss.SetVerificationURIPadding(pad)
		writeState(w, iss, "verification uri padded")
	})

	// Reset: default identity, no polls counted, unpadded verification URI. Cases
	// call this first so the poll count they assert on is their own.
	mux.HandleFunc("/control/reset", func(w http.ResponseWriter, r *http.Request) {
		iss.Reset()
		iss.Script(testoidc.Pending)
		writeState(w, iss, "reset")
	})

	// State: what the next poll will get, and how many have arrived. A case
	// waits on `polls` to know the broker really is polling before it approves —
	// approving earlier would test a race, not a device flow.
	mux.HandleFunc("/control/state", func(w http.ResponseWriter, r *http.Request) {
		writeState(w, iss, "")
	})

	return mux
}

func writeState(w http.ResponseWriter, iss *testoidc.Issuer, action string) {
	claims := iss.Claims()
	body := map[string]any{
		"outcome":     string(iss.NextOutcome()),
		"polls":       iss.Polls(),
		"username":    claims["preferred_username"],
		"groups":      claims["groups"],
		"uri_padding": iss.VerificationURIPadding(),
	}
	if action != "" {
		body["action"] = action
		log.Printf("fakeoidc: control: %s (outcome=%v username=%v groups=%v)",
			action, body["outcome"], body["username"], body["groups"])
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("fakeoidc: write control response: %v", err)
	}
}

// splitGroups turns the groups query parameter into a claim value. An empty
// value means "no groups", which has to be an empty list rather than a list
// containing "": the broker's group check must see the user in nothing.
func splitGroups(raw string) []string {
	groups := []string{}
	for _, g := range strings.Split(raw, ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	return groups
}

// logRequests records every OIDC request, so `docker compose logs fakeoidc`
// shows what the broker actually asked for when a case fails.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("fakeoidc: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
