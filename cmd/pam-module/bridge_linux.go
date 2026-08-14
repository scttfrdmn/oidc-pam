//go:build linux

package main

/*
#cgo CFLAGS: -I${SRCDIR} -I/usr/include/security -Wall -Wextra
#cgo LDFLAGS: -lpam -ljson-c
#include "cgo_bridge.h"
*/
import "C"

import "github.com/scttfrdmn/oidc-pam/pkg/pam"

// This file is what makes cgo compile cgo_bridge_linux.c into the shared object:
// cgo builds the C sources of a package only if some file in that package
// imports "C". It also holds the package's #cgo directives, which cgo merges
// across every file — declaring them once here keeps -lpam from being repeated
// per file.
//
// It is Linux-only because the C depends on Linux-PAM (<security/pam_ext.h>) and
// json-c, neither of which exists on macOS. The .c file carries a _linux
// filename suffix rather than a //go:build line because build constraints in C
// comments are not honoured — the suffix is what the go tool reads.
//
// Keeping the "C" import behind a build tag is also what lets `go build ./...`
// and `go test ./...` run on a developer's Mac (#141). On a non-Linux host this
// package compiles to a trivial main with no C in it, which is why `make
// build-pam` refuses to run outside Linux instead of quietly emitting an empty
// module.

// pamCodesFromHeaders is every PAM result code pkg/pam declares, read from the
// headers this module is compiled against.
//
// pkg/pam spells those codes out as Go literals so it needs no cgo; this map is
// how TestPAMResultCodesMatchHeaders checks the literals still agree with reality.
// It lives in a normal .go file because cgo is not permitted in _test.go files.
var pamCodesFromHeaders = map[string]pam.PAMResultCode{
	"PAM_SUCCESS":          C.PAM_SUCCESS,
	"PAM_SERVICE_ERR":      C.PAM_SERVICE_ERR,
	"PAM_SYSTEM_ERR":       C.PAM_SYSTEM_ERR,
	"PAM_PERM_DENIED":      C.PAM_PERM_DENIED,
	"PAM_AUTH_ERR":         C.PAM_AUTH_ERR,
	"PAM_AUTHINFO_UNAVAIL": C.PAM_AUTHINFO_UNAVAIL,
	"PAM_MAXTRIES":         C.PAM_MAXTRIES,
	"PAM_IGNORE":           C.PAM_IGNORE,
}
