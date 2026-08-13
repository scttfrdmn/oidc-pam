// Command pam-module produces pam_oidc.so, the PAM module that talks to the
// oidc-auth broker.
//
// The PAM entry points — pam_sm_authenticate and the other five — are
// implemented in C, in cgo_bridge_linux.c. They live in *this* package and not
// in pkg/pam because cgo compiles only the C sources sitting in the directory of
// the package being built. An earlier layout kept them in pkg/pam, which this
// package does not import, so `go build -buildmode=c-shared ./cmd/pam-module`
// succeeded and produced a shared object containing no PAM entry points at all
// (#140). Header-only linkage made it silent: the compiler saw valid
// declarations from cgo_bridge.h, nothing referenced libpam, and the linker
// dropped -lpam as unused.
//
// Two things keep that from happening again: the C is here, and `make build-pam`
// refuses to finish unless nm finds all six pam_sm_* symbols in the result.
package main

// This binary is never executed. Building it as c-shared is what emits the
// module, and PAM calls into the C entry points directly; main() exists only
// because package main requires it.
func main() {}
