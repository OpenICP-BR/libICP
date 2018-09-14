package main

// #import "helper.h"
import "C"

import (
	"unsafe"

	"github.com/OpenICP-BR/libICP"
	pointer "github.com/mattn/go-pointer"
)

func new_vec_ptr(src []interface{}) []unsafe.Pointer {
	ans := make([]unsafe.Pointer, len(src))
	for i, v := range src {
		ans[i] = unsafe.Pointer(&v)
	}
	return ans
}

//export FreeGoStuff
func FreeGoStuff(ptr unsafe.Pointer) {
	pointer.Unref(ptr)
}

//export Version
func Version() *C.char {
	return C.CString(libICP.Version())
}

//export CodedErrorGetErrorStr
func CodedErrorGetErrorStr(ptr unsafe.Pointer) *C.char {
	errc := pointer.Restore(ptr).(libICP.CodedError)
	return C.CString(errc.CodeString())
}

//export CodedErrorGetErrorInt
func CodedErrorGetErrorInt(ptr unsafe.Pointer) C.int {
	errc := pointer.Restore(ptr).(libICP.CodedError)
	return C.int(errc.Code())
}

//export ErrorStr
func ErrorStr(ptr unsafe.Pointer) *C.char {
	err := pointer.Restore(ptr).(error)
	return C.CString(err.Error())
}

func main() {}
