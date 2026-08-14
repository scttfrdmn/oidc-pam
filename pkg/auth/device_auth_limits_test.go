package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// startDeviceFlowAgainst runs StartDeviceFlow against a provider that answers the
// device authorization request with resp.
func startDeviceFlowAgainst(t *testing.T, resp DeviceAuthResponse) (*DeviceFlow, error) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)

	provider := &OIDCProvider{
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

	return provider.StartDeviceFlow(&AuthRequest{UserID: "testuser", LoginType: "ssh"})
}

// #162: the verification URI reaches the PAM module three times over — as
// device_url, as text in the instructions, and as QR art whose size grows with it
// — and the module reads the whole response into a fixed 8 KiB buffer. A provider
// that answers with a kilobyte-long URI would make every login on the host fail to
// parse the response, so it is refused here, where the error can name the field.
func TestStartDeviceFlowRejectsOverlongProviderStrings(t *testing.T) {
	valid := DeviceAuthResponse{
		DeviceCode:      "device-code",
		UserCode:        "WDJB-MJHT",
		VerificationURI: "https://idp.example.com/device",
		ExpiresIn:       600,
		Interval:        5,
	}

	tests := []struct {
		name     string
		mutate   func(*DeviceAuthResponse)
		wantText string
	}{
		{
			name: "verification_uri over the limit",
			mutate: func(r *DeviceAuthResponse) {
				r.VerificationURI = "https://idp.example.com/device?x=" + strings.Repeat("A", 513)
			},
			wantText: "verification_uri",
		},
		{
			name: "verification_uri_complete over the limit",
			mutate: func(r *DeviceAuthResponse) {
				r.VerificationURIComplete = "https://idp.example.com/device?code=" + strings.Repeat("A", 513)
			},
			wantText: "verification_uri_complete",
		},
		{
			name: "user_code over the limit",
			mutate: func(r *DeviceAuthResponse) {
				r.UserCode = strings.Repeat("C", maxUserCodeLen+1)
			},
			wantText: "user_code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := valid
			tt.mutate(&resp)

			flow, err := startDeviceFlowAgainst(t, resp)
			if err == nil {
				t.Fatalf("StartDeviceFlow accepted an over-long %s; the response it produces cannot be "+
					"parsed by the PAM module (device_url is %d bytes)", tt.wantText, len(flow.DeviceURL))
			}
			if !strings.Contains(err.Error(), tt.wantText) {
				t.Errorf("error does not name the offending field %q: %v", tt.wantText, err)
			}
		})
	}
}

// The limits are bounds on the absurd, not on the real: values at the limit, and
// every URI an actual provider issues, are accepted unchanged.
func TestStartDeviceFlowAcceptsStringsAtTheLimit(t *testing.T) {
	prefix := "https://idp.example.com/device?user_code="
	atLimit := prefix + strings.Repeat("u", maxVerificationURILen-len(prefix))

	flow, err := startDeviceFlowAgainst(t, DeviceAuthResponse{
		DeviceCode:              "device-code",
		UserCode:                strings.Repeat("C", maxUserCodeLen),
		VerificationURI:         "https://idp.example.com/device",
		VerificationURIComplete: atLimit,
		ExpiresIn:               600,
		Interval:                5,
	})
	if err != nil {
		t.Fatalf("StartDeviceFlow rejected values at the limit: %v", err)
	}
	if flow.DeviceURL != atLimit {
		t.Errorf("device URL = %q, want the complete verification URI unchanged", flow.DeviceURL)
	}
}
