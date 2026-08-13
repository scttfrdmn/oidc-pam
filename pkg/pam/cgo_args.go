package pam

/*
#cgo CFLAGS: -I${SRCDIR} -I/usr/include/security -Wall -Wextra
#cgo LDFLAGS: -lpam -ljson-c
#include <stdlib.h>
#include "cgo_bridge.h"
*/
import "C"

import "unsafe"

// maxSocketPath is the platform's sockaddr_un.sun_path size (108 on Linux, 104
// on Darwin/BSD) — the longest broker socket path the module can use.
const maxSocketPath = int(C.MAX_SOCKET_PATH)

// moduleArgs is the Go view of pam_oidc_options.
type moduleArgs struct {
	socketPath     string
	timeoutSeconds int
}

// parseModuleArgs runs the C parse_arguments() over args — the module arguments
// as PAM would pass them from /etc/pam.d/<service> — and returns the options it
// settled on.
//
// The module's argument handling lives in C because that is where PAM enters the
// module; this wrapper exists so it can be tested from Go (cgo is not permitted
// in _test.go files).
func parseModuleArgs(args []string) moduleArgs {
	var opts C.pam_oidc_options

	argv := make([]*C.char, len(args))
	for i, a := range args {
		argv[i] = C.CString(a)
	}
	defer func() {
		for _, p := range argv {
			C.free(unsafe.Pointer(p))
		}
	}()

	var argvPtr **C.char
	if len(argv) > 0 {
		argvPtr = (**C.char)(unsafe.Pointer(&argv[0]))
	}
	C.parse_arguments(C.int(len(args)), argvPtr, &opts)

	return moduleArgs{
		socketPath:     C.GoString(&opts.socket_path[0]),
		timeoutSeconds: int(opts.timeout_s),
	}
}
