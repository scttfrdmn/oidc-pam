//go:build linux
// +build linux

package pam

/*
#cgo CFLAGS: -I${SRCDIR} -I/usr/include/security
#cgo LDFLAGS: -lpam -ljson-c
*/
import "C"
