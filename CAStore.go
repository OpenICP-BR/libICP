package icp

import (
	"time"

	icp_errs "github.com/gjvnq/libICP/errs"
	iicp "github.com/gjvnq/libICP/iicp"
)

type CAStore struct {
	base *iicp.CAStore
}

// This function MUST be used for this struct.
func NewCAStore(AutoDownload bool) *CAStore {
	store := &CAStore{}
	store.base = iicp.NewCAStore(AutoDownload)
	return store
}

// For now, this functions verifies: validity, integrity, propper chain of certification.
//
// Some of the error codes this may return are: ERR_NOT_BEFORE_DATE, ERR_NOT_AFTER_DATE, ERR_BAD_SIGNATURE, ERR_ISSUER_NOT_FOUND, ERR_MAX_DEPTH_REACHED
func (store CAStore) VerifyCert(cert *Certificate) ([]*Certificate, []icp_errs.CodedError, []icp_errs.CodedWarning) {
	path, errs, warns := store.base.VerifyCertAt(cert.base, time.Now())
	return iicpCertSlice2CertSlice(path), errs, warns
}

// This function will attempt download all CAs from ITI's official website. This runs regardless of CAStore.AutoDownload
func (store *CAStore) DownloadAllCAs() error {
	return store.base.DownloadAllCAs()
}

func (store *CAStore) AddCA(cert *Certificate) []icp_errs.CodedError {
	return store.base.AddCAatTime(cert.base, time.Now())
}

func (store CAStore) WaitDownloads() {
	store.base.WaitDownloads()
}
