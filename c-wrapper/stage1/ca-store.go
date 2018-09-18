package main

// #include "helper.h"
import "C"

import (
	"unsafe"

	"github.com/OpenICP-BR/libICP"
	pointer "github.com/mattn/go-pointer"
)

//export CAStoreAutoDownload
func CAStoreAutoDownload(ptr unsafe.Pointer) bool {
	store := pointer.Restore(ptr).(*libICP.CAStore)
	return store.AutoDownload
}

//export CAStoreAutoDownloadSet
func CAStoreAutoDownloadSet(ptr unsafe.Pointer, val bool) {
	store := pointer.Restore(ptr).(*libICP.CAStore)
	store.AutoDownload = val
}

//export CAStoreDebug
func CAStoreDebug(ptr unsafe.Pointer) bool {
	store := pointer.Restore(ptr).(*libICP.CAStore)
	return store.Debug
}

//export CAStoreDebugSet
func CAStoreDebugSet(ptr unsafe.Pointer, val bool) {
	store := pointer.Restore(ptr).(*libICP.CAStore)
	store.Debug = val
}

//export NewCAStore
func NewCAStore(AutoDownload bool) unsafe.Pointer {
	store := libICP.NewCAStore(AutoDownload)
	ptr := pointer.Save(store)
	return ptr
}

//export CAStoreVerifyCert
func CAStoreVerifyCert(store_ptr unsafe.Pointer, cert_ptr unsafe.Pointer, chain **unsafe.Pointer, errs **unsafe.Pointer, warns **unsafe.Pointer) C.int {
	store := pointer.Restore(store_ptr).(*libICP.CAStore)
	cert := pointer.Restore(cert_ptr).(*libICP.Certificate)

	ans_chain, ans_errs, ans_warns := store.VerifyCert(cert)

	*chain = C.new_voids_ptr(C.int(len(ans_chain)))
	*errs = C.new_voids_ptr(C.int(len(ans_errs)))
	*warns = C.new_voids_ptr(C.int(len(ans_warns)))

	for i := range ans_chain {
		ptr := pointer.Save(&ans_chain[i])
		C.set_voids_ptr(*chain, C.int(i), ptr)
	}
	for i := range ans_errs {
		ptr := pointer.Save(ans_errs[i])
		C.set_voids_ptr(*errs, C.int(i), ptr)
	}
	for i := range ans_warns {
		ptr := pointer.Save(ans_warns[i])
		C.set_voids_ptr(*errs, C.int(i), ptr)
	}

	return C.int(len(ans_errs))
}

//export CAStoreDownloadAll
func CAStoreDownloadAll(ptr unsafe.Pointer) {
	store := pointer.Restore(ptr).(*libICP.CAStore)
	store.DownloadAllCAs()
}

//export CAStoreAddCA
func CAStoreAddCA(ptr, cert_ptr unsafe.Pointer, errs **unsafe.Pointer) C.int {
	store := pointer.Restore(ptr).(*libICP.CAStore)
	cert := pointer.Restore(ptr).(*libICP.Certificate)

	ans_errs := store.AddCA(cert)
	*errs = C.new_voids_ptr(C.int(len(ans_errs)))

	for i := range ans_errs {
		ptr := pointer.Save(ans_errs[i])
		C.set_voids_ptr(*errs, C.int(i), ptr)
	}

	return C.int(len(ans_errs))
}

//export CAStoreAddTestingRootCA
func CAStoreAddTestingRootCA(ptr, cert_ptr unsafe.Pointer, errs **unsafe.Pointer) C.int {
	store := pointer.Restore(ptr).(*libICP.CAStore)
	cert := pointer.Restore(ptr).(*libICP.Certificate)

	ans_errs := store.AddTestingRootCA(cert)
	*errs = C.new_voids_ptr(C.int(len(ans_errs)))

	for i := range ans_errs {
		ptr := pointer.Save(ans_errs[i])
		C.set_voids_ptr(*errs, C.int(i), ptr)
	}

	return C.int(len(ans_errs))
}
