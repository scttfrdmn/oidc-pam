// Command pam-module holds the source of pam_oidc.so, the PAM module that talks
// to the oidc-auth broker.
//
// The module itself is C. The PAM entry points — pam_sm_authenticate and the
// other five — are implemented in cgo_bridge_linux.c, they call no Go, and this
// package exports no Go function to C, so scripts/build-pam-module.sh compiles
// that one file with the C compiler and links it against libpam and json-c. That
// is the whole shipped artifact: 70 KB of C, with no Go runtime in it.
//
// Building it instead as a Go c-shared library, which is what this project used to
// do, produced the same six entry points inside a 2.4 MB object that starts the Go
// runtime in every process that dlopens it. In sshd's pre-auth children that
// means the runtime's threads, its handlers for SIGSEGV, SIGBUS, SIGFPE, SIGPIPE
// and SIGURG installed over sshd's own, and DF_1_NODELETE so the library can
// never be unloaded — none of it in service of any Go code, since none runs
// (#198). If something in this module ever does need to call Go, the c-shared
// build and everything in that list comes back with it.
//
// The Go files here are cgo test wrappers: they drive the C from `go test` (cgo
// is not permitted in _test.go files, so the wrappers live in normal ones). They
// are not part of the module.
//
// The C is in *this* package rather than pkg/pam because cgo compiles only the C
// sources sitting in the directory of the package being built, and pkg/pam is a
// package this one does not import — so the c-shared build of an earlier layout
// succeeded and produced a shared object with no PAM entry points in it at all
// (#140). Header-only linkage made it silent: the compiler saw valid declarations
// from cgo_bridge.h, nothing referenced libpam, and the linker dropped -lpam as
// unused. scripts/check-cgo-quarantine.sh keeps the C here so the tests still
// compile it, and scripts/build-pam-module.sh refuses to finish unless nm finds
// all six pam_sm_* symbols in what it built.
package main

// This binary is never executed and is not what ships; the module is built from
// the C. main() exists only because package main requires it, and package main is
// what lets the cgo test wrappers live alongside the C they exercise.
func main() {}
