//go:build linux

package main

// The package's #cgo CFLAGS/LDFLAGS live in bridge_linux.go.
//
// Every unsafe.Pointer in this file and its siblings carries a `#nosec G103`
// annotation. G103 asks that uses of unsafe be audited, which is the right default
// — so rather than excluding the rule for the repository, each site says which of
// the two shapes it is:
//
//   - C.free(unsafe.Pointer(p)) — releasing a C.CString this function allocated.
//     There is no other way to spell it; C.CString returns *C.char and C.free takes
//     void*.
//   - (**C.char)(unsafe.Pointer(&slice[0])) — handing C the address of Go memory.
//     These obey cgo's pointer-passing rules: the slice outlives the call, the C
//     side does not retain the pointer past it, and the element type is a C type,
//     so nothing here can be moved or collected while C holds it.
//
// None of this is shipped. Since #198 the module PAM loads is compiled from C
// alone; these wrappers exist so `go test` can drive that C, because cgo is not
// permitted in _test.go files.

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
		C.free(unsafe.Pointer(cSocketPath)) // #nosec G103 -- cgo: freeing a C.CString allocation
		C.free(unsafe.Pointer(cUsername))   // #nosec G103 -- cgo: freeing a C.CString allocation
		C.free(unsafe.Pointer(cService))    // #nosec G103 -- cgo: freeing a C.CString allocation
		C.free(unsafe.Pointer(cRhost))      // #nosec G103 -- cgo: freeing a C.CString allocation
		C.free(unsafe.Pointer(cTTY))        // #nosec G103 -- cgo: freeing a C.CString allocation
	}()

	return pam.PAMResultCode(C.perform_authentication(nil, cSocketPath, cUsername, cService, cRhost, cTTY,
		C.int(timeoutSeconds)))
}

// pamHandle is a real pam_handle_t from pam_start. perform_authentication
// tolerates a NULL handle and then shows the user nothing, so a NULL one cannot
// exercise anything the PAM conversation touches; these tests need a handle whose
// items the module actually reads.
type pamHandle struct {
	h *C.pam_handle_t
}

// startPAMHandleWithoutConversation returns a handle whose PAM_CONV item holds no
// conversation function — what a service that never set one presents to the module
// (#168).
//
// libpam will not store a NULL conv *pointer* (pam_set_item refuses it), so a conv
// struct with a NULL function is the reachable shape of "no conversation", and it
// is the one that used to be called through. display_message guards both.
func startPAMHandleWithoutConversation(service, user string) (*pamHandle, pam.PAMResultCode) {
	cService := C.CString(service)
	cUser := C.CString(user)
	defer func() {
		C.free(unsafe.Pointer(cService)) // #nosec G103 -- cgo: freeing a C.CString allocation
		C.free(unsafe.Pointer(cUser))    // #nosec G103 -- cgo: freeing a C.CString allocation
	}()

	var conv C.struct_pam_conv // zero value: no conversation function, no appdata
	var handle *C.pam_handle_t

	rc := pam.PAMResultCode(C.pam_start(cService, cUser, &conv, &handle))
	if rc != pam.PAMSuccess {
		return nil, rc
	}
	return &pamHandle{h: handle}, rc
}

func (p *pamHandle) close() {
	C.pam_end(p.h, C.PAM_SUCCESS)
}

// smAuthenticate drives pam_sm_authenticate itself, so the module's argument
// parsing is part of what is exercised rather than being bypassed the way
// performAuthentication bypasses it.
func smAuthenticate(p *pamHandle, args []string) pam.PAMResultCode {
	argv := make([]*C.char, len(args))
	for i, a := range args {
		argv[i] = C.CString(a)
	}
	defer func() {
		for _, arg := range argv {
			C.free(unsafe.Pointer(arg)) // #nosec G103 -- cgo: freeing a C.CString allocation
		}
	}()

	var argvPtr **C.char
	if len(argv) > 0 {
		argvPtr = (**C.char)(unsafe.Pointer(&argv[0])) // #nosec G103 -- cgo: passing the address of Go-allocated memory to C
	}

	return pam.PAMResultCode(C.pam_sm_authenticate(p.h, 0, C.int(len(args)), argvPtr))
}

// debugLoggingEnabled reports whether the module is currently logging at
// LOG_DEBUG. The module writes to syslog, which a test cannot read, so this is how
// a test observes that the `debug` argument of one invocation does not carry into
// the next (#168).
func debugLoggingEnabled() bool {
	return C.debug_logging_enabled() != 0
}

// classifyLoginTypeC exposes the C module's login-type classification so a Go
// test can assert it agrees with GetLoginType. The two must match: the broker
// applies per-login-type policy, and the C module and the Go client would
// otherwise get different answers for the same login.
func classifyLoginTypeC(service, tty string) string {
	cService := C.CString(service)
	cTTY := C.CString(tty)
	defer func() {
		C.free(unsafe.Pointer(cService)) // #nosec G103 -- cgo: freeing a C.CString allocation
		C.free(unsafe.Pointer(cTTY))     // #nosec G103 -- cgo: freeing a C.CString allocation
	}()

	return C.GoString(C.classify_login_type(cService, cTTY))
}

// acctMgmtVerdict exposes the C module's account-phase verdict to Go tests.
func acctMgmtVerdict() pam.PAMResultCode {
	return pam.PAMResultCode(C.acct_mgmt_verdict())
}

// brokerPending is the C module's BROKER_PENDING: classifyBrokerResponse's answer
// for a device flow that has been started but not finished, which is neither a
// grant nor a denial. Named from the header rather than written as -1 so the two
// cannot drift.
const brokerPending = int(C.BROKER_PENDING)

// classifyBrokerResponse runs the C module's decision over the exact bytes a broker
// would put on the wire — parse, then classify_response — and returns the PAM result
// code it reached, or brokerPending.
//
// This is the module's whole verdict on a reply, and until now nothing called it:
// both classify_response and map_error_code are static, the Go tests here drove them
// only indirectly through a fake broker that a real one resembles, and e2e cannot
// construct a malformed reply at all. A decision nothing tests is a decision that can
// be deleted without a single suite noticing (#197).
func classifyBrokerResponse(response string) int {
	cResponse := C.CString(response)
	defer C.free(unsafe.Pointer(cResponse)) // #nosec G103 -- cgo: freeing a C.CString allocation

	return int(C.classify_response_text(cResponse))
}

// mapBrokerErrorCode runs the C module's error_code -> PAM result mapping, the
// second half of the same decision: which kind of denial a refusal becomes.
//
// A nil code is the NULL the module is handed whenever error_code is absent or is
// not a JSON string — the case a Go string cannot express, and the one that has to
// stay a denial (#197).
func mapBrokerErrorCode(code *string) pam.PAMResultCode {
	if code == nil {
		return pam.PAMResultCode(C.map_error_code((*C.char)(nil)))
	}

	cCode := C.CString(*code)
	defer C.free(unsafe.Pointer(cCode)) // #nosec G103 -- cgo: freeing a C.CString allocation

	return pam.PAMResultCode(C.map_error_code(cCode))
}
