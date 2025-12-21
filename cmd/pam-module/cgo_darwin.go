//go:build darwin
// +build darwin

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../pkg/pam -I/opt/homebrew/include -I/usr/include/security
#cgo LDFLAGS: -lpam -ljson-c -L/opt/homebrew/lib
*/
import "C"
