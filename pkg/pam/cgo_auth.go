package pam

/*
#cgo CFLAGS: -I${SRCDIR} -I/usr/include/security -Wall -Wextra
#cgo LDFLAGS: -lpam -ljson-c
#include <stdlib.h>
#include "cgo_bridge.h"
*/
import "C"

import "unsafe"

// performAuthentication runs the C module's auth phase — the same code path
// pam_sm_authenticate takes — against the broker listening on socketPath, and
// returns the PAM result code it produced.
//
// The PAM handle is NULL, so no conversation messages are shown; everything else
// (the initial authenticate request, the device-flow polling loop, and the
// terminal-state mapping) behaves exactly as it does under a real PAM stack.
// This wrapper lives in a normal .go file because cgo is not permitted in
// _test.go files.
func performAuthentication(socketPath, username, service, rhost, tty string, timeoutSeconds int) PAMResultCode {
	cSocketPath := C.CString(socketPath)
	cUsername := C.CString(username)
	cService := C.CString(service)
	cRhost := C.CString(rhost)
	cTTY := C.CString(tty)
	defer func() {
		C.free(unsafe.Pointer(cSocketPath))
		C.free(unsafe.Pointer(cUsername))
		C.free(unsafe.Pointer(cService))
		C.free(unsafe.Pointer(cRhost))
		C.free(unsafe.Pointer(cTTY))
	}()

	return PAMResultCode(C.perform_authentication(nil, cSocketPath, cUsername, cService, cRhost, cTTY,
		C.int(timeoutSeconds)))
}
