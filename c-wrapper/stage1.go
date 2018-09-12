package main

import "C"

import (
	"github.com/OpenICP-BR/libICP"
	"unsafe"
)

func new_vec_ptr(src []interface{}) []unsafe.Pointer {
	ans := make([]unsafe.Pointer, len(src))
	for i, v := range src {
		ans[i] = unsafe.Pointer(&v)
	}
	return ans
}

//export Version
func Version() *C.char {
	return C.CString(libICP.Version())
}

//export CodedErrorGetErrorStr
func CodedErrorGetErrorStr(ptr unsafe.Pointer) *C.char {
	err := *(*libICP.CodedError)(ptr)
	return C.CString(err.CodeString())
}

//export CodedErrorGetErrorInt
func CodedErrorGetErrorInt(ptr unsafe.Pointer) C.int {
	err := *(*libICP.CodedError)(ptr)
	return C.int(err.Code())
}

//export NewCertificate
func NewCertificate() unsafe.Pointer {
	cert := new(libICP.Certificate)
	return unsafe.Pointer(cert)
}

//export NewCertificateFromFile
func NewCertificateFromFile(path string, certs []unsafe.Pointer, errs []unsafe.Pointer) {
	ans_certs, ans_errs := libICP.NewCertificateFromFile(path)
	certs = make([]unsafe.Pointer, len(ans_certs))
	errs = make([]unsafe.Pointer, len(ans_errs))

	for i, v := range ans_certs {
		certs[i] = unsafe.Pointer(&v)
	}
	for i, v := range ans_errs {
		errs[i] = unsafe.Pointer(&v)
	}
}

func main() {}
