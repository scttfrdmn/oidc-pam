//go:build linux

package ipc

import (
	"fmt"
	"net"
	"syscall"
)

// getPeerCredentials extracts the UID and GID of the peer process from a Unix socket connection
// using the SO_PEERCRED socket option (Linux only).
func getPeerCredentials(conn net.Conn) (uid, gid uint32, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("connection is not a Unix socket")
	}

	f, err := unixConn.File()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get file descriptor: %w", err)
	}
	defer f.Close()

	cred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get peer credentials: %w", err)
	}

	return cred.Uid, cred.Gid, nil
}
