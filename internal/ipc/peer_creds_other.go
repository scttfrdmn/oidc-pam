//go:build !linux

package ipc

import (
	"fmt"
	"net"
)

// verifyPeerCredentials is a stub on non-Linux platforms.
// SO_PEERCRED peer verification is only supported on Linux.
// Deploy this service on Linux in production.
func verifyPeerCredentials(conn net.Conn) error {
	if conn == nil {
		return fmt.Errorf("nil connection")
	}
	return fmt.Errorf("peer credential verification not supported on this platform; deploy on Linux")
}
