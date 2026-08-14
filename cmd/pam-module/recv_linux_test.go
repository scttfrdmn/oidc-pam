//go:build linux

package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Tests for the read timeout in receive_auth_response.
//
// The timeout used to be per-poll: the full RESPONSE_READ_TIMEOUT_MS was handed to
// every poll() inside the read loop, so a peer that produced one byte just inside
// each window reset the clock, and the real bound was one window per byte of the
// buffer — MAX_RESPONSE_SIZE-1 = 16 383 windows of 30 s, about 5.7 days. The
// function's own comment promised a total bound (#196).
//
// What that costs is not abstract. The read happens inside pam_sm_authenticate,
// which under sshd runs in the pre-auth child, and sshd's LoginGraceTime — 120 s by
// default — is the point at which sshd kills that child itself. A module still
// waiting when that happens gives the user a dropped connection with no explanation
// and leaves nothing in auth.log naming the broker as the cause: the module never
// got to decide anything, so it never got to say anything. A total bound is what
// keeps the verdict, and the log line, on this side.
//
// These tests supply their own short budget through receive_auth_response_within.
// Waiting out the shipped 30 s — let alone the 5.7 days the per-poll version allowed
// — is not something a test suite can do, which is a large part of why this code
// went untested.

// brokerPeer is one end of a connected socket pair standing in for the broker: a raw
// blocking file descriptor for the module to read from, and a writer the test uses
// to decide exactly when — and whether — bytes appear.
//
// A socket pair rather than a Unix listener because what is under test is the timing
// of the bytes, and nothing here needs a broker that speaks the protocol.
type brokerPeer struct {
	moduleFD int
	peer     *os.File
}

func newBrokerPeer(t *testing.T) *brokerPeer {
	t.Helper()

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}

	p := &brokerPeer{moduleFD: fds[0], peer: os.NewFile(uintptr(fds[1]), "broker-peer")}

	t.Cleanup(func() {
		_ = p.peer.Close()
		_ = syscall.Close(p.moduleFD)
	})

	return p
}

// dribble writes data one byte at a time, every interval, until it runs out or the
// socket is closed under it. This is the hostile shape: every byte lands inside a
// fresh poll() window, so a per-poll timeout never fires.
func (p *brokerPeer) dribble(t *testing.T, data string, interval time.Duration) {
	t.Helper()

	go func() {
		for i := 0; i < len(data); i++ {
			time.Sleep(interval)
			if _, err := p.peer.Write([]byte(data[i : i+1])); err != nil {
				return // the module gave up and the test closed the socket
			}
		}
	}()
}

// A peer that keeps sending, never finishes a message, and never lets a single poll
// time out must still be cut off — by the total budget, which is the only thing
// bounding it.
//
// The numbers are the test: 300 bytes at 20 ms is 6 s of dribbling, and the buffer
// is large enough to hold all of it, so the per-poll version would have sat here for
// those 6 s and then reported the buffer full. With the budget as a total, the read
// ends after ~500 ms with a timeout.
func TestReceiveAuthResponseBoundsTheWholeReadNotEachPoll(t *testing.T) {
	t.Parallel()

	const (
		budgetMS = 500
		bufSize  = 512
	)

	peer := newBrokerPeer(t)
	peer.dribble(t, strings.Repeat("x", 300), 20*time.Millisecond)

	start := time.Now()
	rc, got := receiveAuthResponseWithin(peer.moduleFD, bufSize, budgetMS)
	elapsed := time.Since(start)

	if rc != recvError {
		t.Fatalf("a peer dribbling bytes forever returned rc=%d (%q), want recvError (%d): the "+
			"read is bounded by the byte count, not by time", rc, got, recvError)
	}
	// Generously above the 500 ms budget and far below the 6 s the per-poll version
	// would have taken, so a slow machine cannot make this pass or fail by accident.
	if elapsed > 3*time.Second {
		t.Fatalf("the read took %s against a %dms total budget: each poll() is getting a fresh "+
			"budget, so a peer that sends one byte per window holds the login open for as long "+
			"as it likes — which is what sshd's LoginGraceTime then ends, with no explanation "+
			"to the user", elapsed, budgetMS)
	}
}

// The simple case, and the one the old code did get right: a peer that says nothing
// at all is cut off when the budget runs out. It is here because the deadline
// arithmetic is what now produces this timeout, and because it pins the other half
// of the bound — the read must not give up *early* either, or a broker that is
// merely slow is reported as a broken one.
func TestReceiveAuthResponseTimesOutOnASilentBroker(t *testing.T) {
	t.Parallel()

	const budgetMS = 400

	peer := newBrokerPeer(t)

	start := time.Now()
	rc, got := receiveAuthResponseWithin(peer.moduleFD, 512, budgetMS)
	elapsed := time.Since(start)

	if rc != recvError {
		t.Fatalf("a silent broker returned rc=%d (%q), want recvError (%d)", rc, got, recvError)
	}
	if elapsed < 300*time.Millisecond {
		t.Fatalf("gave up after %s of a %dms budget: a broker that is slow to answer must not be "+
			"reported as one that is not answering", elapsed, budgetMS)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("gave up after %s, well past the %dms budget", elapsed, budgetMS)
	}
}

// The deadline must not break the reason the loop exists. A response that arrives in
// several pieces — which is every response large enough to be split, and the whole
// point of looping on recv() (#162) — still has to be read in full while there is
// budget for it.
func TestReceiveAuthResponseStillReadsAResponseThatArrivesInPieces(t *testing.T) {
	t.Parallel()

	const reply = `{"success":true,"session_id":"s","requires_device":false}` + "\n"

	peer := newBrokerPeer(t)
	// One byte every 2 ms: ~115 ms in total, comfortably inside the budget, and
	// enough separate recv() calls that a single-read implementation could not pass.
	peer.dribble(t, reply, 2*time.Millisecond)

	rc, got := receiveAuthResponseWithin(peer.moduleFD, 512, 5000)
	if rc != recvOK {
		t.Fatalf("a split response returned rc=%d, want recvOK (%d): the deadline is cutting off "+
			"reads that are making progress, which refuses logins the module could have served",
			rc, recvOK)
	}
	if got != reply {
		t.Fatalf("read %q, want %q", got, reply)
	}
}

// The timeout and the buffer bound are separate bounds and must stay separately
// reported: an oversized response is a fault in the contract between the broker and
// this module (PAM_SERVICE_ERR), while a timeout is a broker that did not answer
// (PAM_AUTHINFO_UNAVAIL). Confusing the two sends an operator to look at the wrong
// thing (#162).
func TestReceiveAuthResponseStillReportsAFullBufferWithNoEndOfMessage(t *testing.T) {
	t.Parallel()

	peer := newBrokerPeer(t)
	// Promptly, so the budget is nowhere near exhausted, and with no newline in it.
	if _, err := peer.peer.Write([]byte(strings.Repeat("Q", 64))); err != nil {
		t.Fatalf("write: %v", err)
	}

	rc, _ := receiveAuthResponseWithin(peer.moduleFD, 16, 5000)
	if rc != recvResponseTooLarge {
		t.Fatalf("rc=%d, want recvResponseTooLarge (%d)", rc, recvResponseTooLarge)
	}
}

// A zero-length buffer has nowhere to put even the NUL terminator. It cannot happen
// from inside the module, which always passes sizeof(response); it is here so the
// bound is checked before the deadline arithmetic rather than after.
func TestReceiveAuthResponseRejectsAZeroLengthBuffer(t *testing.T) {
	t.Parallel()

	peer := newBrokerPeer(t)

	if rc, _ := receiveAuthResponseWithin(peer.moduleFD, 0, 5000); rc != recvError {
		t.Fatalf("rc=%d, want recvError (%d)", rc, recvError)
	}
}
