//go:build darwin

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// xucredVersion0 is the expected struct version returned by LOCAL_PEERCRED on
// macOS (XUCRED_VERSION). x/sys/unix does not export a constant for it.
const xucredVersion0 = 0

// getPeerCredentials extracts the UID and GID of the peer process from a Unix socket connection
// using the LOCAL_PEERCRED socket option (macOS/Darwin).
//
// The descriptor is reached through withSocketFD rather than (*net.UnixConn).File():
// File()+Fd() clears O_NONBLOCK on the connection and so voids its read deadline for
// the rest of the connection's life (#216).
func getPeerCredentials(conn net.Conn) (uid, gid uint32, err error) {
	var cred *unix.Xucred
	if err := withSocketFD(conn, func(fd int) error {
		var credErr error
		cred, credErr = unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		return credErr
	}); err != nil {
		return 0, 0, fmt.Errorf("failed to get peer credentials: %w", err)
	}

	// Reject an unexpected/zeroed struct version so an unpopulated Xucred is not
	// misread as uid 0 (root) (L-2).
	if cred.Version != xucredVersion0 {
		return 0, 0, fmt.Errorf("unexpected xucred version %d", cred.Version)
	}

	// Xucred has Uid and Groups[0..Ngroups-1]; Groups[0] is the primary GID
	var gidVal uint32
	if cred.Ngroups > 0 {
		gidVal = cred.Groups[0]
	}

	return cred.Uid, gidVal, nil
}
