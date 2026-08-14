//go:build linux

package ipc

import (
	"fmt"
	"net"
	"syscall"
)

// getPeerCredentials extracts the UID and GID of the peer process from a Unix socket connection
// using the SO_PEERCRED socket option (Linux only).
//
// This is the only place the kernel is asked for a peer's identity on Linux;
// verifyPeerCredentials is layered on top of it. There used to be a second,
// independent implementation here that reached the descriptor through
// (*net.UnixConn).File(), which silently cleared O_NONBLOCK on the connection and
// so voided the read deadline for the rest of that connection's life — see the
// comment on withSocketFD and #216.
func getPeerCredentials(conn net.Conn) (uid, gid uint32, err error) {
	var cred *syscall.Ucred
	if err := withSocketFD(conn, func(fd int) error {
		var credErr error
		cred, credErr = syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		return credErr
	}); err != nil {
		return 0, 0, fmt.Errorf("failed to get peer credentials: %w", err)
	}
	return cred.Uid, cred.Gid, nil
}
