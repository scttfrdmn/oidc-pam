package auth

import (
	"errors"
	"testing"
)

// TestClassifyPollError covers M-5: polling errors must map to a bounded set of
// metric label values, never the raw error string.
func TestClassifyPollError(t *testing.T) {
	cases := map[string]string{
		"": "OK", // nil handled separately
		"ID token nonce mismatch (possible replay)": "NONCE_INVALID",
		"failed to verify ID token: bad sig":        "ID_TOKEN_INVALID",
		"ID token claim validation failed: age":     "ID_TOKEN_INVALID",
		"token error: access_denied":                "TOKEN_ERROR",
		"device code expired":                       "EXPIRED",
		"failed to decode token response":           "DECODE_ERROR",
		"failed to poll device authorization: dial": "NETWORK_ERROR",
		"something entirely unexpected":             "POLL_FAILED",
		// (#167) A grant carrying no ID token at all is its own condition, and the
		// message has to be able to say which checks were impossible without being
		// classified as one of them having failed.
		`provider "idp" granted the device authorization but returned no id_token, so this ` +
			`authorization cannot be verified at all`: "ID_TOKEN_MISSING",
	}
	for msg, want := range cases {
		var err error
		if msg != "" {
			err = errors.New(msg)
		}
		got := classifyPollError(err)
		if msg == "" {
			if got != "OK" {
				t.Errorf("nil error: got %q, want OK", got)
			}
			continue
		}
		if got != want {
			t.Errorf("classifyPollError(%q) = %q, want %q", msg, got, want)
		}
	}
}
