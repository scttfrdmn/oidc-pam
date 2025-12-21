//go:build linux
// +build linux

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../pkg/pam -I/usr/include/security
#cgo LDFLAGS: -lpam -ljson-c
*/
import "C"
