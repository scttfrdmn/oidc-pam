//go:build linux

package ipc

import (
	"fmt"
	"net"
)

// verifyPeerCredentials checks that the connecting process is running as root (UID 0)
// and returns its uid. PAM modules always run as root, so non-root connections are
// rejected. The uid is returned so the caller can key a peer's malformed-request
// budget on it (#189).
//
// The kernel lookup itself lives in getPeerCredentials so there is exactly one of
// it: this function used to carry its own copy of the SO_PEERCRED call, and the two
// copies drifted — one of them reached the descriptor in a way that disabled the
// connection's read deadline (#216).
func verifyPeerCredentials(conn net.Conn) (uint32, error) {
	uid, _, err := getPeerCredentials(conn)
	if err != nil {
		return 0, err
	}
	if uid != 0 {
		return uid, fmt.Errorf("peer UID %d is not root", uid)
	}
	return uid, nil
}
