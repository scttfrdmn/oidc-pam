//go:build darwin
// +build darwin

package pam

/*
#cgo CFLAGS: -I${SRCDIR} -I/opt/homebrew/include -I/usr/include/security
#cgo LDFLAGS: -lpam -ljson-c -L/opt/homebrew/lib
*/
import "C"
