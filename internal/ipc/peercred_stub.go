//go:build !linux && !darwin && !freebsd

package ipc

import (
	"fmt"
	"net"
)

// getPeerCredentials is a stub for platforms with no supported peer-credential
// mechanism. It FAILS CLOSED: returning an error ensures an unverifiable peer is
// rejected rather than being treated as root (uid 0). Never return (0, 0, nil)
// here — that would silently authorize every connection on an unsupported port.
func getPeerCredentials(conn net.Conn) (uid, gid uint32, err error) {
	return 0, 0, fmt.Errorf("peer credential verification is not supported on this platform; deploy on Linux")
}
