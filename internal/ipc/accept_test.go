package ipc

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The accept loop must survive an accept(2) failure that says nothing about the
// listener.
//
// EMFILE is the one that matters: an unprivileged local user opens connections
// until the broker's descriptor table is full, and the next accept fails. The loop
// used to return on any non-timeout error, which left a process that is still
// running — systemd sees it healthy, Restart=always never fires, nothing in the
// journal reads as fatal — and that never accepts another connection. On a host
// wired with configs/pam/ssh, `auth sufficient pam_oidc.so` then fails for every
// login and falls through to pam_deny (#216).
func TestAcceptLoopSurvivesATransientAcceptError(t *testing.T) {
	server, err := NewServer(filepath.Join(t.TempDir(), "unused.sock"), nil, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// net.Pipe rather than a real socket: it is not a *net.UnixConn, so
	// verifyPeerCredentials rejects it identically on every platform and this test
	// asserts the same thing whether or not it runs as root on Linux.
	handlerSide, peerSide := net.Pipe()

	listener := &scriptedListener{}
	listener.push(nil, &net.OpError{Op: "accept", Net: "unix", Err: syscall.EMFILE})
	listener.push(handlerSide, nil)

	server.listener = listener
	server.wg.Add(1)
	go server.acceptConnections(context.Background())
	t.Cleanup(func() { _ = server.Stop() })

	// The connection offered *after* the EMFILE has to be served. Reading the
	// rejection off it is the proof: the handler ran.
	if err := peerSide.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	payload, err := readOneResponse(peerSide)
	if err != nil {
		t.Fatalf("the connection offered after an EMFILE was never handled (%v): the accept "+
			"loop exited on the first non-timeout error, so the broker keeps running but "+
			"accepts nothing for the rest of its life (#216)", err)
	}
	if len(payload) == 0 {
		t.Fatal("handler wrote nothing to the connection accepted after an EMFILE")
	}

	if got := listener.acceptCalls(); got < 2 {
		t.Errorf("Accept was called %d time(s); the loop stopped accepting after the "+
			"EMFILE (#216)", got)
	}
}

// A closed listener is the one accept error that does mean stop: Stop closes it, and
// retrying forever would leak a goroutine per Server for the life of the process.
func TestAcceptLoopStopsWhenTheListenerIsClosed(t *testing.T) {
	server, err := NewServer(filepath.Join(t.TempDir(), "unused.sock"), nil, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	listener := &scriptedListener{}
	listener.push(nil, &net.OpError{Op: "accept", Net: "unix", Err: net.ErrClosed})

	server.listener = listener
	server.wg.Add(1)
	// Stop unblocks the loop if it did not return by itself, so a failure here is
	// reported rather than hanging the package's test binary.
	t.Cleanup(func() { _ = server.Stop() })
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		server.acceptConnections(context.Background())
	}()

	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("accept loop is still running after net.ErrClosed: Stop would block " +
			"forever waiting for it")
	}
}

// scriptedListener hands out a prepared sequence of accept results and then blocks
// until it is closed, which is what a real listener does between connections.
type scriptedListener struct {
	mu      sync.Mutex
	results []acceptResult
	calls   atomic.Int64

	closeOnce sync.Once
	closed    chan struct{}
	initOnce  sync.Once
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func (l *scriptedListener) init() {
	l.initOnce.Do(func() { l.closed = make(chan struct{}) })
}

func (l *scriptedListener) push(conn net.Conn, err error) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.results = append(l.results, acceptResult{conn, err})
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.init()
	l.calls.Add(1)

	l.mu.Lock()
	if len(l.results) > 0 {
		next := l.results[0]
		l.results = l.results[1:]
		l.mu.Unlock()
		return next.conn, next.err
	}
	l.mu.Unlock()

	<-l.closed
	return nil, &net.OpError{Op: "accept", Net: "unix", Err: net.ErrClosed}
}

func (l *scriptedListener) Close() error {
	l.init()
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr { return scriptedAddr{} }

func (l *scriptedListener) acceptCalls() int { return int(l.calls.Load()) }

type scriptedAddr struct{}

func (scriptedAddr) Network() string { return "unix" }
func (scriptedAddr) String() string  { return "scripted" }
