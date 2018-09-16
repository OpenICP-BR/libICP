package main

// #include "helper.h"
import "C"

import (
	"unsafe"

	"github.com/OpenICP-BR/libICP"
	pointer "github.com/mattn/go-pointer"
)

//export NewPFXFromFile
func NewPFXFromFile(path *C.char, password *C.char, err_ptr *unsafe.Pointer) unsafe.Pointer {
	pfx, err := libICP.NewPFXFromFile(C.GoString(path), C.GoString(password))
	*err_ptr = pointer.Save(err)

	return pointer.Save(&pfx)
}

//export PFXCert
func PFXCert(pfx_ptr unsafe.Pointer) unsafe.Pointer {
	pfx := pointer.Restore(pfx_ptr).(*libICP.PFX)
	cert := pfx.Cert
	return pointer.Save(&cert)
}

//export PFXHasKey
func PFXHasKey(pfx_ptr unsafe.Pointer) bool {
	pfx := pointer.Restore(pfx_ptr).(*libICP.PFX)
	return pfx.HasKey()
}

//export PFXSaveCertToFile
func PFXSaveCertToFile(pfx_ptr unsafe.Pointer, path *C.char, err_ptr *unsafe.Pointer) bool {
	pfx := pointer.Restore(pfx_ptr).(*libICP.PFX)
	err := pfx.SaveCertToFile(C.GoString(path))

	*err_ptr = pointer.Save(err)

	return err == nil
}

//export PFXSaveToFile
func PFXSaveToFile(pfx_ptr unsafe.Pointer, path *C.char, password *C.char, err_ptr *unsafe.Pointer) bool {
	pfx := pointer.Restore(pfx_ptr).(*libICP.PFX)
	err := pfx.SaveToFile(C.GoString(path), C.GoString(password))

	*err_ptr = pointer.Save(err)

	return err == nil
}
