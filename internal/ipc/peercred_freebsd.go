//go:build freebsd

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// getPeerCredentials extracts the UID and GID of the peer process from a Unix socket connection
// using the LOCAL_PEERCRED socket option (FreeBSD).
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

	cred, err := unix.GetsockoptXucred(int(f.Fd()), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get peer credentials: %w", err)
	}

	// Xucred has Uid and Groups[0..Ngroups-1]; Groups[0] is the primary GID
	var gidVal uint32
	if cred.Ngroups > 0 {
		gidVal = cred.Groups[0]
	}

	return cred.Uid, gidVal, nil
}
