//go:build linux

package main

import (
	"os"
	"testing"

	"github.com/scttfrdmn/oidc-pam/pkg/pam"
)

// What the C client actually puts on the wire for the two fields that say where a
// login came from and where it is going (#169).
//
// The module sent no source_ip at all, and sent PAM_RHOST — the address the user
// connects *from* — as target_host. Downstream, an empty source_ip is not treated
// as "unknown" but as "bad": require_private_network went through
// isPrivateIP(""), which is false, and refused every login on the host.
//
// This is the C half of the same claim TestAuthenticateSendsSourceIPAndThisHost
// makes about the Go client in pkg/pam. The defect was identical in both, which is
// what a boundary with a test on only one side of it produces.
func TestAuthRequestCarriesSourceIPAndThisHost(t *testing.T) {
	t.Parallel()

	thisHost, err := os.Hostname()
	if err != nil {
		t.Skipf("no hostname on this machine: %v", err)
	}

	tests := []struct {
		name         string
		rhost        string
		wantSourceIP string // "" means the field must be absent
		wantRHost    string // metadata.rhost; "" means absent
	}{
		{"an IPv4 peer", "10.0.0.1", "10.0.0.1", "10.0.0.1"},
		{"an IPv6 peer", "2001:db8::1", "2001:db8::1", "2001:db8::1"},
		{"an IPv6 peer with a zone", "fe80::1%eth0", "fe80::1%eth0", "fe80::1%eth0"},
		// sshd hands PAM a resolved name when UseDNS is on. source_ip carries an
		// address or nothing, so the name is audit context only.
		{"a resolved hostname is not an address", "client.example.com", "", "client.example.com"},
		// A console login has no peer, and the broker must be able to tell that from
		// a peer it could not evaluate.
		{"no peer at all", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			broker := newFakeBroker(t, func(_ int, _ map[string]interface{}) interface{} {
				return authenticated("sess-src")
			})

			if got := performAuthentication(broker.socketPath, "testuser", "sshd", tt.rhost, "pts/0", 30); got != pam.PAMSuccess {
				t.Fatalf("performAuthentication = %d, want pam.PAMSuccess", got)
			}

			requests := broker.received()
			if len(requests) != 1 {
				t.Fatalf("expected exactly one request, got %d", len(requests))
			}
			req := requests[0]

			if got := jsonString(req, "source_ip"); got != tt.wantSourceIP {
				t.Errorf("source_ip = %q, want %q (PAM_RHOST was %q)", got, tt.wantSourceIP, tt.rhost)
			}
			if got := jsonString(req, "target_host"); got != thisHost {
				t.Errorf("target_host = %q, want this host %q — target_host is the machine being "+
					"logged into, not the address the login came from", got, thisHost)
			}
			metadata, _ := req["metadata"].(map[string]interface{})
			if got := jsonString(metadata, "rhost"); got != tt.wantRHost {
				t.Errorf("metadata.rhost = %q, want %q: the unabridged rhost belongs in the audit "+
					"context even when it is not an address", got, tt.wantRHost)
			}
		})
	}
}

func jsonString(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}
