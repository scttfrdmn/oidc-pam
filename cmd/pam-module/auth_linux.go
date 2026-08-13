//go:build linux

package main

// The package's #cgo CFLAGS/LDFLAGS live in bridge_linux.go.

/*
#include <stdlib.h>
#include "cgo_bridge.h"
*/
import "C"

import (
	"unsafe"

	"github.com/scttfrdmn/oidc-pam/pkg/pam"
)

// performAuthentication runs the C module's auth phase — the same code path
// pam_sm_authenticate takes — against the broker listening on socketPath, and
// returns the PAM result code it produced.
//
// The PAM handle is NULL, so no conversation messages are shown; everything else
// (the initial authenticate request, the device-flow polling loop, and the
// terminal-state mapping) behaves exactly as it does under a real PAM stack.
// This wrapper lives in a normal .go file because cgo is not permitted in
// _test.go files.
func performAuthentication(socketPath, username, service, rhost, tty string, timeoutSeconds int) pam.PAMResultCode {
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

	return pam.PAMResultCode(C.perform_authentication(nil, cSocketPath, cUsername, cService, cRhost, cTTY,
		C.int(timeoutSeconds)))
}

// classifyLoginTypeC exposes the C module's login-type classification so a Go
// test can assert it agrees with GetLoginType. The two must match: the broker
// applies per-login-type policy, and the C module and the Go client would
// otherwise get different answers for the same login.
func classifyLoginTypeC(service, tty string) string {
	cService := C.CString(service)
	cTTY := C.CString(tty)
	defer func() {
		C.free(unsafe.Pointer(cService))
		C.free(unsafe.Pointer(cTTY))
	}()

	return C.GoString(C.classify_login_type(cService, cTTY))
}

// acctMgmtVerdict exposes the C module's account-phase verdict to Go tests.
func acctMgmtVerdict() pam.PAMResultCode {
	return pam.PAMResultCode(C.acct_mgmt_verdict())
}
