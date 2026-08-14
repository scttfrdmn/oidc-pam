//go:build linux || darwin || freebsd

package ipc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A peer-credential lookup must not disturb the connection it inspects.
//
// The obvious implementation — (*net.UnixConn).File() and then Fd() — does. Fd()
// puts the descriptor back into blocking mode, and because dup(2) shares the open
// file description, O_NONBLOCK is cleared on the connection itself. The runtime
// poller is then bypassed for that connection and SetDeadline has no effect, so a
// client that connects and sends nothing holds its handler goroutine (and an OS
// thread) for the life of the process. With maxConcurrentConnections handlers stuck
// that way the broker answers nothing at all, and on a host wired with
// configs/pam/ssh that denies every login (#216).
//
// This runs wherever getPeerCredentials is implemented, including this project's
// macOS development hosts: the defect was reported against the Linux file, but the
// Darwin and FreeBSD implementations had copied the same idiom.
func TestPeerCredentialLookupLeavesTheReadDeadlineWorking(t *testing.T) {
	serverConn, clientConn := unixConnPairForTest(t)

	if _, _, err := getPeerCredentials(serverConn); err != nil {
		t.Fatalf("getPeerCredentials: %v", err)
	}

	// The mechanism, checked directly: the connection must still be non-blocking,
	// which is what lets the runtime poller enforce deadlines on it.
	if flags := fileStatusFlags(t, serverConn); flags&unix.O_NONBLOCK == 0 {
		t.Errorf("getPeerCredentials cleared O_NONBLOCK on the connection (flags %#o): the "+
			"runtime poller is now bypassed and SetDeadline is a no-op for the rest of "+
			"this connection's life (#216)", flags)
	}

	// The consequence, checked behaviourally: the peer sends nothing, so this read
	// must come back as a timeout rather than blocking forever. Note that the peer
	// end is deliberately left open — closing it would end the read with EOF and
	// prove nothing.
	if err := serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := serverConn.Read(buf)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		netErr, ok := err.(net.Error)
		if !ok || !netErr.Timeout() {
			t.Errorf("read after getPeerCredentials returned %v, want a deadline-exceeded "+
				"timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("read is still blocked 5s after a 200ms read deadline: getPeerCredentials " +
			"voided the deadline, so a client that sends nothing pins this handler " +
			"goroutine forever (#216)")

		// Unblock the reader before returning. It is parked in a blocking read(2)
		// holding a reference to the descriptor, and (*net.UnixConn).Close waits
		// for that reference to be dropped — so leaving it there would hang the
		// test's cleanup instead of reporting the failure above.
		_ = clientConn.Close()
		<-readDone
	}
}

// unixConnPairForTest returns the two ends of a connected Unix socket, server end
// first. Both are closed when the test finishes.
func unixConnPairForTest(t *testing.T) (server, client net.Conn) {
	t.Helper()

	// os.MkdirTemp rather than t.TempDir: a Unix socket path is limited to ~104
	// bytes on macOS and t.TempDir embeds the (long) test name.
	dir, err := os.MkdirTemp("", "ipcpair-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	listener, err := net.Listen("unix", filepath.Join(dir, "s.sock"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	type accepted struct {
		conn net.Conn
		err  error
	}
	accepts := make(chan accepted, 1)
	go func() {
		conn, err := listener.Accept()
		accepts <- accepted{conn, err}
	}()

	client, err = net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	got := <-accepts
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}
	t.Cleanup(func() { _ = got.conn.Close() })

	return got.conn, client
}

// fileStatusFlags returns the F_GETFL flags of a connection's descriptor. It uses
// SyscallConn().Control, which — unlike File() — has no side effect on the flags it
// is reporting.
func fileStatusFlags(t *testing.T, conn net.Conn) int {
	t.Helper()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("connection is %T, want *net.UnixConn", conn)
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var flags int
	var flagsErr error
	if err := rawConn.Control(func(fd uintptr) {
		flags, flagsErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if flagsErr != nil {
		t.Fatalf("F_GETFL: %v", flagsErr)
	}
	return flags
}
