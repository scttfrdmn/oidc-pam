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
func getPeerCredentials(conn net.Conn) (uid, gid uint32, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("connection is not a Unix socket")
	}

	f, err := unixConn.File()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get file descriptor: %w", err)
	}
	// File() returns a duplicate descriptor, so closing it does not disturb conn;
	// there is nothing to do about a failure to close a descriptor we only read a
	// sockopt from. Matches peercred_linux.go.
	defer func() { _ = f.Close() }()

	cred, err := unix.GetsockoptXucred(int(f.Fd()), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
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
