//go:build linux

package main

// The package's #cgo CFLAGS/LDFLAGS live in bridge_linux.go.

/*
#include "cgo_bridge.h"
*/
import "C"

import "unsafe"

// The RECV_* results receive_auth_response can report, as cgo_bridge.h defines
// them, so a test names the module's own constants rather than restating -1 and -2.
const (
	recvOK               = int(C.RECV_OK)
	recvError            = int(C.RECV_ERROR)
	recvResponseTooLarge = int(C.RECV_RESPONSE_TOO_LARGE)
)

// receiveAuthResponseWithin reads one broker response from fd into a buffer of
// bufSize bytes, allowing totalTimeoutMS for the whole read, and returns the RECV_*
// result together with whatever was read.
//
// The budget is a parameter only so that a test can use a short one. The module
// itself always reads through receive_auth_response, which supplies the real
// RESPONSE_READ_TIMEOUT_MS of 30 s; no test should have to wait 30 s to learn
// whether the bound holds, and before #196 it would have had to wait rather longer
// than that — the bound was per-poll, so a peer dribbling one byte per window could
// hold the read for MAX_RESPONSE_SIZE-1 windows, about 5.7 days. Everything else
// here is the production read path.
//
// bufSize is a parameter for the same reason: it keeps "a full buffer with no end of
// message in it" reachable without moving 16 KiB through a socket.
//
// This wrapper lives in a normal .go file because cgo is not permitted in _test.go
// files.
func receiveAuthResponseWithin(fd, bufSize, totalTimeoutMS int) (int, string) {
	buf := make([]byte, bufSize)

	var into *C.char
	if bufSize > 0 {
		into = (*C.char)(unsafe.Pointer(&buf[0]))
	}

	rc := int(C.receive_auth_response_within(C.int(fd), into, C.size_t(bufSize),
		C.int(totalTimeoutMS)))

	// The C side NUL-terminates within bufSize, so the response is the bytes up to
	// that NUL; C.GoString of a nil pointer is the empty string.
	return rc, C.GoString(into)
}
