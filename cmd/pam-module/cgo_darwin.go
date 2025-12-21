//go:build darwin
// +build darwin

package main

/*
#cgo CFLAGS: -I/opt/homebrew/include
#cgo LDFLAGS: -ljson-c -L/opt/homebrew/lib
*/
import "C"
