//go:build !linux

package ipc

import (
	"net"

	"github.com/rs/zerolog/log"
)

// getPeerCredentials is a no-op stub for non-Linux platforms where SO_PEERCRED is not available.
// It returns uid=0, gid=0, nil to allow connections (peer auth verification is skipped).
func getPeerCredentials(conn net.Conn) (uid, gid uint32, err error) {
	log.Warn().Msg("Peer credential verification is not available on this platform")
	return 0, 0, nil
}
