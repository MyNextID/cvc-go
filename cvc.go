package main

/*
#cgo CFLAGS: -I./include
#cgo darwin,arm64 LDFLAGS: -L./lib/darwin/arm64 -lcvc
#cgo darwin,amd64 LDFLAGS: -L./lib/darwin/x86_64 -lcvc
#cgo linux,amd64 LDFLAGS: -L./lib/linux/x86_64 -lcvc
#cgo linux,arm64 LDFLAGS: -L./lib/linux/aarch64 -lcvc
#cgo windows,amd64 LDFLAGS: -L./lib/windows/x86_64 -lcvc

#include "crypto.h"
*/
import "C"

// CVCHelloWorld calls the C function cvc_hello_world and returns the result as a Go string
func CVCHelloWorld() string {
	cStr := C.cvc_hello_world()
	goStr := C.GoString(cStr)
	return goStr
}

func CVCTestMiraclBigAdd() bool {
	result := C.cvc_test_miracl_big_add()
	return int(result) == 1
}
