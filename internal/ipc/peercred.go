package ipc

import (
	"fmt"
	"net"
)

// withSocketFD runs fn on the file descriptor underlying a Unix socket connection.
//
// The obvious way to reach a descriptor — (*net.UnixConn).File() — must not be used
// here. net.conn.File() hands the duplicate to os.newFile as kindSock with
// nonBlocking=true, which sets File.nonblock so that Fd() calls pfd.SetBlocking(),
// i.e. syscall.SetNonblock(fd, false). dup(2) shares the open file description, and
// therefore the file status flags, with the original descriptor: clearing
// O_NONBLOCK on the duplicate clears it on the connection. From that point a read
// on the connection blocks in the kernel, the runtime poller never sees it, and the
// deadline set by handleConnection cannot fire — one client that connects and sends
// nothing then holds its handler goroutine for the life of the process (#216).
// os.File.Fd's own documentation states the consequence: "On Unix and Windows,
// File.SetDeadline methods will stop working."
//
// SyscallConn().Control has no such side effect. It pins the descriptor for the
// duration of the callback and leaves its status flags alone, so every
// peer-credential lookup in this package goes through here.
func withSocketFD(conn net.Conn, fn func(fd int) error) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("connection is not a Unix socket")
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw connection: %w", err)
	}
	var fnErr error
	if err := rawConn.Control(func(fd uintptr) { fnErr = fn(int(fd)) }); err != nil {
		return fmt.Errorf("failed to access socket descriptor: %w", err)
	}
	return fnErr
}
