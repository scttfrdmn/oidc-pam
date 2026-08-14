package ipc

import (
	"fmt"
	"os"
	"syscall"
)

// verifySocketDirTrusted refuses to let the broker bind inside a directory that an
// account other than root or the broker itself can write to.
//
// The socket's own 0660 root mode does not protect it: write permission on the
// *directory* is enough to unlink(2) the socket and bind(2) a replacement at the
// same path. The real broker keeps serving on its now-unlinked inode, logs nothing
// and stays green in `systemctl status`, while every PAM login connects to the
// impostor — which can answer {"success":true} and, with the shipped
// `auth sufficient pam_oidc.so`, short-circuit the whole auth stack. That is
// authentication as any user, including root, from whatever account owns the
// directory (#200).
//
// The installers created exactly that: mkdir 0755 followed by
// `chown -R oidc-auth:oidc-auth`, for an account no shipped component runs as. The
// systemd unit now has systemd create and own the directory
// (RuntimeDirectory=oidc-auth, RuntimeDirectoryMode=0750), which also resets mode
// and ownership on every start; this check is the part that does not depend on the
// host being wired up correctly.
//
// Scope, stated plainly: this checks the socket's own directory, not its ancestors.
// A writable ancestor would let an attacker rename the directory rather than the
// socket, but /run and /var are root-owned on any host where the rest of this
// service makes sense, and walking to / would reject an ordinary $TMPDIR.
func verifySocketDirTrusted(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("cannot stat socket directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("socket directory %s is not a directory", dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Fail closed: an unknown owner is an unverified owner.
		return fmt.Errorf("cannot determine the owner of socket directory %s", dir)
	}
	return checkSocketDirOwnership(dir, st.Uid, info.Mode(), os.Geteuid())
}

// checkSocketDirOwnership holds the actual rule, separated from the stat(2) call so
// it can be tested for owners this process cannot create on disk.
//
// The rule: nobody but root and the broker's own uid may write into the directory
// the socket lives in. Ownership by the broker's own uid is accepted so that a
// developer running the broker as themselves — and the package's own tests, in
// $TMPDIR — are not required to be root.
func checkSocketDirOwnership(dir string, owner uint32, mode os.FileMode, euid int) error {
	if perm := mode.Perm(); perm&0022 != 0 {
		return fmt.Errorf("socket directory %s has mode %04o: group- or other-writable, "+
			"so any account with that access can unlink the broker's socket and bind an "+
			"impostor in its place (#200)", dir, perm)
	}
	if owner != 0 && owner != uint32(euid) { // #nosec G115 -- a uid always fits uint32
		return fmt.Errorf("socket directory %s is owned by uid %d, which is neither root "+
			"nor this process (uid %d): that account can unlink the broker's socket and "+
			"bind an impostor in its place (#200)", dir, owner, euid)
	}
	return nil
}
