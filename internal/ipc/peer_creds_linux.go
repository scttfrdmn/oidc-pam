//go:build linux

package ipc

import (
	"fmt"
	"net"
	"syscall"
)

// verifyPeerCredentials checks that the connecting process is running as root (UID 0).
// PAM modules always run as root, so non-root connections are rejected.
func verifyPeerCredentials(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("connection is not a Unix socket")
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw connection: %w", err)
	}
	var cred *syscall.Ucred
	var credErr error
	_ = rawConn.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if credErr != nil {
		return fmt.Errorf("failed to get peer credentials: %w", credErr)
	}
	if cred.Uid != 0 {
		return fmt.Errorf("peer UID %d is not root", cred.Uid)
	}
	return nil
}
