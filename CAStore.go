package libICP

import (
	"time"

	icp "github.com/gjvnq/libICP/icp"
)

type CAStore struct {
	base *icp.CAStore
}

// This function MUST be used for this struct.
func NewCAStore(AutoDownload bool) *CAStore {
	store := &CAStore{}
	store.base = icp.NewCAStore(AutoDownload)
	return store
}

// For now, this functions verifies: validity, integrity, propper chain of certification.
//
// Some of the error codes this may return are: ERR_NOT_BEFORE_DATE, ERR_NOT_AFTER_DATE, ERR_BAD_SIGNATURE, ERR_ISSUER_NOT_FOUND, ERR_MAX_DEPTH_REACHED
func (store CAStore) VerifyCert(cert *Certificate) ([]*Certificate, []icp.CodedError, []icp.CodedWarning) {
	path, errs, warns := store.base.VerifyCertAt(cert.base, time.Now())
	return icpCertSlice2CertSlice(path), errs, warns
}

// This function will attempt download all CAs from ITI's official website. This runs regardless of CAStore.AutoDownload
func (store *CAStore) DownloadAllCAs() error {
	return store.base.DownloadAllCAs()
}

func (store *CAStore) AddCA(cert *Certificate) []icp.CodedError {
	return store.base.AddCAatTime(cert.base, time.Now())
}

func (store CAStore) WaitDownloads() {
	store.base.WaitDownloads()
}
