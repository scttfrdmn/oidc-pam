package auth

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// #219: the device code is the credential that completes a login. Whoever holds
// one while the flow is open can redeem the token the user is about to approve,
// from anywhere, with no IdP account of their own — and the user's own login then
// either succeeds or fails with a used-code error they read as a glitch. The user
// code, and the verification_uri_complete that embeds it, approve the flow.
//
// None of them may be written down. The two places they were: a debug log line in
// StartDeviceFlow — debug being the level DEPLOYMENT.md tells operators to turn on
// while a login is failing, which is when a code is live — and the pending
// session's TokenFingerprint field.

// captureLogsAtDebug points the global logger at a buffer and lowers the level to
// debug for the duration of the test, so a test can assert on what an operator
// following the troubleshooting instructions would find in the journal.
func captureLogsAtDebug(t *testing.T) *bytes.Buffer {
	t.Helper()

	buf := &bytes.Buffer{}
	savedLogger, savedLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(buf).Level(zerolog.DebugLevel)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() {
		log.Logger = savedLogger
		zerolog.SetGlobalLevel(savedLevel)
	})
	return buf
}

func TestDeviceFlowLogsNoCodeAtDebugLevel(t *testing.T) {
	const (
		deviceCode = "dc-9f41c7a2e6b8d035-live-device-code"
		userCode   = "WDJB-MJHT"
	)
	completeURI := "https://idp.example.com/device?user_code=" + userCode

	logs := captureLogsAtDebug(t)

	flow, err := startDeviceFlowAgainst(t, DeviceAuthResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         "https://idp.example.com/device",
		VerificationURIComplete: completeURI,
		ExpiresIn:               600,
		Interval:                5,
	})
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}

	// The flow still carries all three — this is about what is written down, not
	// about what the broker knows.
	if flow.DeviceCode != deviceCode || flow.DeviceURL != completeURI {
		t.Fatalf("the flow did not come back with the provider's values: %+v", flow)
	}

	written := logs.String()
	for _, secret := range []struct{ what, value string }{
		{"device code", deviceCode},
		{"user code", userCode},
		{"complete verification URI", completeURI},
	} {
		if strings.Contains(written, secret.value) {
			t.Errorf("the %s reached the log at debug level; on the shipped unit that is the "+
				"journal, readable by every account in systemd-journal (#219). Logged: %s",
				secret.what, written)
		}
	}

	// The line has to remain worth keeping, or the next person debugging a device
	// flow will put the code back.
	if !strings.Contains(written, "Device flow initiated") {
		t.Errorf("the device flow is no longer logged at all, so nothing records that one "+
			"started: %s", written)
	}
	if !strings.Contains(written, "test-provider") {
		t.Errorf("the log line does not name the provider the flow was started against: %s", written)
	}
}

// A pending session waits on a device flow; it has no token yet, so it has no
// token fingerprint. What it used to hold in that field was the device code
// itself, unhashed — a live credential in a field the code documents, and
// TestSessionHoldsNoTokenMaterial asserts, as a safe-to-copy identifier.
func TestPendingSessionCarriesNoDeviceCode(t *testing.T) {
	env := newDenialTestEnv(t)

	resp, err := env.broker.Authenticate(&AuthRequest{
		UserID:    "testuser",
		SourceIP:  "192.0.2.10",
		LoginType: "ssh",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !resp.Success {
		t.Fatalf("the login was refused before a device flow started: %+v", resp)
	}
	// Let the poll goroutine go before the harness waits on it.
	defer close(env.broker.stopChan)

	session := env.broker.getSession(resp.SessionID)
	if session == nil {
		t.Fatalf("no session was recorded for %q", resp.SessionID)
	}
	if !session.IsActive && session.TokenFingerprint != "" {
		t.Errorf("a pending session carries TokenFingerprint %q. There is no token to "+
			"fingerprint until the flow completes, and what this held was the raw device "+
			"code — the credential that completes this login — in the one field the "+
			"broker treats as safe to copy and record (#219)", session.TokenFingerprint)
	}
}
