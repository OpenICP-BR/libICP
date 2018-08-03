package libICP

import (
	"time"

	rawICP "github.com/gjvnq/libICP/rawICP"
)

type CAStore struct {
	base *rawICP.CAStore
}

// This function MUST be used for this struct.
func NewCAStore(AutoDownload bool) *CAStore {
	store := &CAStore{}
	store.base = rawICP.NewCAStore(AutoDownload)
	return store
}

// For now, this functions verifies: validity, integrity, propper chain of certification.
//
// Some of the error codes this may return are: ERR_NOT_BEFORE_DATE, ERR_NOT_AFTER_DATE, ERR_BAD_SIGNATURE, ERR_ISSUER_NOT_FOUND, ERR_MAX_DEPTH_REACHED
func (store CAStore) VerifyCert(cert *Certificate) ([]*Certificate, []CodedError, []CodedWarning) {
	path, errs, warns := store.base.VerifyCertAt(cert.base, time.Now())
	return rawICPCertSlice2CertSlice(path), rawICPCodedErrorSlice(errs), rawICPCodedWarningSlice(warns)
}

// This function will attempt download all CAs from ITI's official website. This runs regardless of CAStore.AutoDownload
func (store *CAStore) DownloadAllCAs() error {
	return store.base.DownloadAllCAs()
}

func (store *CAStore) AddCA(cert *Certificate) []CodedError {
	return rawICPCodedErrorSlice(store.base.AddCAatTime(cert.base, time.Now()))
}

func (store CAStore) WaitDownloads() {
	store.base.WaitDownloads()
}
