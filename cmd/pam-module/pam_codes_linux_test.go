//go:build linux

package main

import (
	"testing"

	"github.com/scttfrdmn/oidc-pam/pkg/pam"
)

// TestPAMResultCodesMatchHeaders is what keeps pkg/pam's PAMResultCode constants
// honest.
//
// Those constants used to be derived from the PAM headers via cgo, which made
// them correct by construction but also dragged libpam into a package that has no
// other need for C — so pkg/pam could not build or be tested off Linux (#141).
// They are now Go literals, and this test restores the guarantee from the other
// side: each one is compared against the macro of the same name in the headers
// the module is actually compiled against (see pamCodesFromHeaders).
//
// That is a stronger check than deriving them was. Deriving guaranteed the values
// matched whatever headers happened to be present, silently; this fails loudly if
// they ever stop matching, naming the constant and both values.
func TestPAMResultCodesMatchHeaders(t *testing.T) {
	declared := map[string]pam.PAMResultCode{
		"PAM_SUCCESS":          pam.PAMSuccess,
		"PAM_SERVICE_ERR":      pam.PAMServiceError,
		"PAM_SYSTEM_ERR":       pam.PAMSystemError,
		"PAM_PERM_DENIED":      pam.PAMPermDenied,
		"PAM_AUTH_ERR":         pam.PAMAuthError,
		"PAM_AUTHINFO_UNAVAIL": pam.PAMAuthInfoUnavail,
		"PAM_MAXTRIES":         pam.PAMMaxTries,
		"PAM_IGNORE":           pam.PAMIgnore,
	}

	// Every code the headers expose must be one pkg/pam declares, and vice versa:
	// a code added to one side and not the other is the drift this guards against.
	if len(declared) != len(pamCodesFromHeaders) {
		t.Errorf("pkg/pam declares %d PAM codes but %d are checked against the headers; "+
			"update pamCodesFromHeaders in bridge_linux.go", len(declared), len(pamCodesFromHeaders))
	}

	for name, got := range declared {
		want, ok := pamCodesFromHeaders[name]
		if !ok {
			t.Errorf("%s is declared in pkg/pam but not checked against the headers; "+
				"add it to pamCodesFromHeaders in bridge_linux.go", name)
			continue
		}
		if got != want {
			t.Errorf("pkg/pam has %d for %s, but the PAM headers define it as %d; "+
				"fix the constant in pkg/pam/pam.go", got, name, want)
		}
	}
}
