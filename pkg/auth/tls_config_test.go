package auth

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// TestBuildTLSConfigDefault verifies the baseline: TLS 1.2 minimum, no
// custom CA, no skip-verify, no pinning.
func TestBuildTLSConfigDefault(t *testing.T) {
	tlsCfg, err := buildTLSConfig(config.SecurityConfig{})
	if err != nil {
		t.Fatalf("buildTLSConfig() unexpected error: %v", err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion=TLS1.2, got %d", tlsCfg.MinVersion)
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify=false by default")
	}
	if tlsCfg.RootCAs != nil {
		t.Error("Expected RootCAs=nil (use system pool) by default")
	}
	if tlsCfg.VerifyPeerCertificate != nil {
		t.Error("Expected VerifyPeerCertificate=nil by default")
	}
}

// TestBuildTLSConfigSkipVerify checks that SkipTLSVerify sets InsecureSkipVerify.
func TestBuildTLSConfigSkipVerify(t *testing.T) {
	tlsCfg, err := buildTLSConfig(config.SecurityConfig{
		TLSVerification: config.TLSVerification{SkipTLSVerify: true},
	})
	if err != nil {
		t.Fatalf("buildTLSConfig() unexpected error: %v", err)
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify=true when SkipTLSVerify is set")
	}
}

// TestBuildTLSConfigCABundle verifies that TrustedCABundle is loaded into
// RootCAs and that HTTPS requests to a server using that CA succeed.
func TestBuildTLSConfigCABundle(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Write the test server's self-signed certificate to a temp PEM file.
	certDER := server.TLS.Certificates[0].Certificate[0]
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	caFile := writeTempFile(t, pemData)

	tlsCfg, err := buildTLSConfig(config.SecurityConfig{
		TLSVerification: config.TLSVerification{TrustedCABundle: caFile},
	})
	if err != nil {
		t.Fatalf("buildTLSConfig() unexpected error: %v", err)
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("Expected RootCAs to be populated")
	}

	// An HTTPS GET to the test server must succeed using the custom CA pool.
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("HTTPS request with custom CA bundle failed: %v", err)
	}
	_ = resp.Body.Close()
}

// TestBuildTLSConfigCABundleInvalidPath expects an error when the CA bundle
// path does not exist.
func TestBuildTLSConfigCABundleInvalidPath(t *testing.T) {
	_, err := buildTLSConfig(config.SecurityConfig{
		TLSVerification: config.TLSVerification{TrustedCABundle: "/nonexistent/ca.pem"},
	})
	if err == nil {
		t.Fatal("Expected error for nonexistent CA bundle path")
	}
}

// TestBuildTLSConfigCABundleInvalidPEM expects an error when the bundle file
// contains no valid PEM certificates.
func TestBuildTLSConfigCABundleInvalidPEM(t *testing.T) {
	caFile := writeTempFile(t, []byte("not valid PEM content"))
	_, err := buildTLSConfig(config.SecurityConfig{
		TLSVerification: config.TLSVerification{TrustedCABundle: caFile},
	})
	if err == nil {
		t.Fatal("Expected error for invalid PEM content in CA bundle")
	}
}

// TestBuildTLSConfigCertPinSuccess verifies that a connection succeeds when
// the server's certificate fingerprint is listed in PinnedCertificates.
func TestBuildTLSConfigCertPinSuccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fp := certFingerprint(server.TLS.Certificates[0].Certificate[0])

	tlsCfg, err := buildTLSConfig(config.SecurityConfig{
		TLSVerification: config.TLSVerification{
			PinnedCertificates: []string{fp},
			SkipTLSVerify:      true, // self-signed cert needs skip-verify for chain validation
		},
	})
	if err != nil {
		t.Fatalf("buildTLSConfig() unexpected error: %v", err)
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Fatal("Expected VerifyPeerCertificate callback to be set")
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Expected success with matching pin, got: %v", err)
	}
	_ = resp.Body.Close()
}

// TestBuildTLSConfigCertPinFailure verifies that a connection is rejected when
// no certificate in the chain matches any pinned fingerprint.
func TestBuildTLSConfigCertPinFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Deliberately wrong fingerprint (64 zeros).
	wrongPin := strings.Repeat("0", 64)

	tlsCfg, err := buildTLSConfig(config.SecurityConfig{
		TLSVerification: config.TLSVerification{
			PinnedCertificates: []string{wrongPin},
			SkipTLSVerify:      true,
		},
	})
	if err != nil {
		t.Fatalf("buildTLSConfig() unexpected error: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
	_, err = client.Get(server.URL)
	if err == nil {
		t.Fatal("Expected connection to be rejected with non-matching pin")
	}
	if !strings.Contains(err.Error(), "pinning") && !strings.Contains(err.Error(), "fingerprint") {
		t.Logf("Error (expected pinning-related): %v", err)
	}
}

// TestBuildTLSConfigCertPinColonFormat verifies that colon-separated
// fingerprints (as printed by openssl x509 -fingerprint -sha256) are accepted.
func TestBuildTLSConfigCertPinColonFormat(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Build colon-separated fingerprint (e.g. "aa:bb:cc:...")
	hash := sha256.Sum256(server.TLS.Certificates[0].Certificate[0])
	var parts []string
	for _, b := range hash {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	colonFP := strings.Join(parts, ":")

	tlsCfg, err := buildTLSConfig(config.SecurityConfig{
		TLSVerification: config.TLSVerification{
			PinnedCertificates: []string{colonFP},
			SkipTLSVerify:      true,
		},
	})
	if err != nil {
		t.Fatalf("buildTLSConfig() unexpected error: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Expected success with colon-separated pin, got: %v", err)
	}
	_ = resp.Body.Close()
}

// TestBuildTLSConfigCertPinUppercase verifies that uppercase hex fingerprints
// are accepted (normalised to lowercase internally).
func TestBuildTLSConfigCertPinUppercase(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fp := strings.ToUpper(certFingerprint(server.TLS.Certificates[0].Certificate[0]))

	tlsCfg, err := buildTLSConfig(config.SecurityConfig{
		TLSVerification: config.TLSVerification{
			PinnedCertificates: []string{fp},
			SkipTLSVerify:      true,
		},
	})
	if err != nil {
		t.Fatalf("buildTLSConfig() unexpected error: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Expected success with uppercase pin, got: %v", err)
	}
	_ = resp.Body.Close()
}

// TestBuildTLSConfigCertPinMultiple verifies that a connection succeeds when
// one of several pinned fingerprints matches.
func TestBuildTLSConfigCertPinMultiple(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	realFP := certFingerprint(server.TLS.Certificates[0].Certificate[0])
	wrongFP := strings.Repeat("0", 64)

	tlsCfg, err := buildTLSConfig(config.SecurityConfig{
		TLSVerification: config.TLSVerification{
			PinnedCertificates: []string{wrongFP, realFP}, // real pin is second
			SkipTLSVerify:      true,
		},
	})
	if err != nil {
		t.Fatalf("buildTLSConfig() unexpected error: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Expected success when one of multiple pins matches: %v", err)
	}
	_ = resp.Body.Close()
}

// helpers

// certFingerprint returns the lowercase hex SHA-256 fingerprint of a
// DER-encoded certificate.
func certFingerprint(certDER []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(certDER))
}

// writeTempFile writes data to a temp file in t.TempDir() and returns its path.
func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	_ = f.Close()
	return f.Name()
}
