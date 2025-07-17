package main

/*
#cgo CFLAGS: -I/usr/include/security -I/opt/homebrew/include
#cgo LDFLAGS: -lpam -ljson-c -L/opt/homebrew/lib
#include "../../pkg/pam/cgo_bridge.h"
*/
import "C"

// This is the main package for the PAM module shared library
// The actual PAM module implementation is in the C code
// This Go code is only used for building the shared library

func main() {
	// This function is never called, but is required for the main package
	// The actual PAM module entry points are in the C code
}