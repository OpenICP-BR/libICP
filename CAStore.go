package libICP

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/ioutil"
	"sync"
	"time"
)

const TESTING_ROOT_CA_SUBJECT = "C=BR/O=Fake ICP-Brasil/OU=Apenas para testes - SEM VALOR LEGAL/CN=Autoridade Certificadora Raiz de Testes - SEM VALOR LEGAL"

// The lack of HTTPS is not a security problem because the root CAs are embedded in libICP and all CAs are checked against them. (see file `data.go`)
const ALL_CAs_ZIP_URL = "http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip"

type CAStore struct {
	// If true, it will attempt to download missing CAs and CRLs
	AutoDownload bool
	cas          map[string]*Certificate
	inited       bool
	wg           *sync.WaitGroup
	Debug        bool
}

func NewCAStore(AutoDownload bool) *CAStore {
	store := &CAStore{
		AutoDownload: AutoDownload,
	}
	store.Init()
	return store
}

// This function MUST be called before using this struct. It makes a few maps and adds the following root CAs: ROOT_CA_BR_ICP_V1, ROOT_CA_BR_ICP_V2, ROOT_CA_BR_ICP_V5
func (store *CAStore) Init() {
	// Do not run this function twice
	if store.inited {
		return
	}
	store.wg = new(sync.WaitGroup)
	// Get our root certificates
	certs, errs := NewCertificateFromBytes([]byte(ROOT_CA_BR_ICP_V1 + ROOT_CA_BR_ICP_V2 + ROOT_CA_BR_ICP_V5))
	if errs != nil {
		for _, err := range errs {
			if err != nil {
				println(err.Error())
			}
		}
		panic(errs)
	}
	// Save them
	store.cas = make(map[string]*Certificate)
	for i, _ := range certs {
		store.direct_add_ca(&certs[i])
	}
	store.inited = true
}

// For now, this functions verifies: validity, integrity, propper chain of certification.
//
// Some of the error codes this may return are: ERR_NOT_BEFORE_DATE, ERR_NOT_AFTER_DATE, ERR_BAD_SIGNATURE, ERR_ISSUER_NOT_FOUND, ERR_MAX_DEPTH_REACHED
func (store CAStore) VerifyCert(cert_to_verify *Certificate) ([]*Certificate, []CodedError, []CodedWarning) {
	return store.verify_cert_at(cert_to_verify, time.Now())
}

func (store CAStore) verify_cert_at(cert_to_verify *Certificate, now time.Time) ([]*Certificate, []CodedError, []CodedWarning) {
	ans_errs := make([]CodedError, 0)
	ans_warns := make([]CodedWarning, 0)
	// Get certification path
	path, err := store.build_path(cert_to_verify, _PATH_BUILDING_MAX_DEPTH)
	if err != nil {
		ans_errs = append(ans_errs, err)
		return nil, ans_errs, nil
	}
	last_ca_max_ca_i := -1
	last_ca_subj := ""

	// Check each certificate
	for i, cert := range path {
		if !now.After(cert.NotBefore) {
			merr := NewMultiError("certificate not yet valid", ERR_NOT_BEFORE_DATE, nil)
			merr.SetParam("cert.NotBefore", cert.NotBefore)
			merr.SetParam("now", now)
			merr.SetParam("cert.Subject", cert.Subject)
			ans_errs = append(ans_errs, merr)
		}
		if !now.Before(cert.NotAfter) {
			merr := NewMultiError("certificate has expired", ERR_NOT_AFTER_DATE, nil)
			merr.SetParam("cert.NotAfter", cert.NotAfter)
			merr.SetParam("now", now)
			merr.SetParam("cert.Subject", cert.Subject)
			ans_errs = append(ans_errs, merr)
		}

		// Take care of the basic constraints extension
		if cert.IsCA() && cert.ext_basic_constraints.Exists && cert.ext_basic_constraints.CA && cert.ext_basic_constraints.PathLen != 0 {
			new_max_i := i + cert.ext_basic_constraints.PathLen
			if last_ca_max_ca_i > 0 && last_ca_max_ca_i > new_max_i {
				last_ca_subj = cert.Subject
				last_ca_max_ca_i = new_max_i
			}
		}
		if cert.IsCA() && i > last_ca_max_ca_i && last_ca_max_ca_i >= 0 {
			merr := NewMultiError("exceded max path basic constraint", ERR_BASIC_CONSTRAINTS_MAX_PATH_EXCEDED, nil)
			merr.SetParam("cert.Subject", cert.Subject)
			merr.SetParam("last_ca.Subject", last_ca_subj)
			ans_errs = append(ans_errs, merr)
		}

		var issuer *Certificate
		if i == len(path)-1 {
			issuer = path[i]
		} else {
			issuer = path[i+1]
		}
		if errs := cert.verify_signed_by(*issuer); errs != nil {
			ans_errs = append(ans_errs, errs...)
		}

		if issuer.is_crl_outdated() && store.AutoDownload {
			go issuer.download_crl(store.wg)
		}
		cert.check_against_issuer_crl(issuer)

		status := cert.CRL_Status
		if status == CRL_REVOKED {
			merr := NewMultiError("certificate revoked (source: CRL)", ERR_REVOKED, nil)
			merr.SetParam("cert.Subject", cert.Subject)
			merr.SetParam("cert.Issuer", cert.Issuer)
			merr.SetParam("crl.ThisUpdate", issuer.crl.TBSCertList.ThisUpdate)
			ans_errs = append(ans_errs, merr)
		}
		if status == CRL_UNSURE_OR_NOT_FOUND {
			merr := NewMultiError("certificate possibly revoked", ERR_UNKOWN_REVOCATION_STATUS, nil)
			merr.SetParam("cert.Subject", cert.Subject)
			merr.SetParam("cert.Issuer", cert.Issuer)
			merr.SetParam("crl.ThisUpdate", issuer.crl.TBSCertList.ThisUpdate)
			ans_warns = append(ans_warns, merr)
		}
	}

	if len(ans_errs) == 0 {
		ans_errs = nil
	}
	if len(ans_warns) == 0 {
		ans_warns = nil
	}
	return path, ans_errs, ans_warns
}

// Adds a new root CA for testing proposes. It MUST have as subject and issuer: TESTING_ROOT_CA_SUBJECT
//
// This should NEVER be used in production!
func (store *CAStore) AddTestingRootCA(cert *Certificate) []CodedError {
	if cert.Subject != cert.Issuer || cert.Subject != TESTING_ROOT_CA_SUBJECT {
		merr := NewMultiError("AddTestingRootCA REQUIRES the testing CA to have a specific subject and issuer", ERR_TEST_CA_IMPROPPER_NAME, nil)
		merr.SetParam("expected-value", TESTING_ROOT_CA_SUBJECT)
		merr.SetParam("actual-subject", cert.Subject)
		merr.SetParam("actual-issuer", cert.Issuer)
		return []CodedError{merr}
	}

	store.direct_add_ca(cert)

	return nil
}

// Adds a new CA (certificate authority) if, and only if, it is valid when check against the existing CAs.
func (store *CAStore) add_ca_at_time(cert *Certificate, now time.Time) []CodedError {
	if !cert.IsCA() {
		if store.Debug {
			fmt.Println("[libICP-DEBUG] INVALID CA: " + cert.Subject)
		}
		return []CodedError{NewMultiError("certificate is not a certificate authority", ERR_NOT_CA, nil)}
	}
	if _, errs, _ := store.verify_cert_at(cert, now); errs != nil {
		return errs
	}
	store.direct_add_ca(cert)
	return nil
}

func (store *CAStore) direct_add_ca(cert *Certificate) {
	if cert == nil {
		return
	}

	// Attempt to download CRL
	if store.AutoDownload {
		store.wg.Add(1)
		go cert.download_crl(store.wg)
		store.wg.Add(1)
		go cert.download_crl(store.wg)
	}

	store.cas[cert.SubjectKeyId] = cert
	store.cas[cert.Subject] = cert

	if store.Debug {
		fmt.Println("[libICP-DEBUG] Added CA: " + cert.Subject)
	}
}

func (store CAStore) WaitDownloads() {
	store.wg.Wait()
}

const _PATH_BUILDING_MAX_DEPTH = 16

func (store CAStore) build_path(end_cert *Certificate, max_depth int) ([]*Certificate, CodedError) {
	if max_depth < 0 {
		merr := NewMultiError("reached maximum depth", ERR_MAX_DEPTH_REACHED, nil)
		merr.SetParam("SubjectKeyID", end_cert.SubjectKeyId)
		merr.SetParam("AuthorityKeyID", end_cert.AuthorityKeyId)
		return nil, merr
	}

	issuer, ok := store.cas[end_cert.AuthorityKeyId]
	if !ok {
		// Try again
		issuer, ok = store.cas[end_cert.Issuer]
	}
	if !ok {
		merr := NewMultiError("issuer not found", ERR_ISSUER_NOT_FOUND, nil)
		merr.SetParam("AuthorityKeyID", end_cert.AuthorityKeyId)
		return nil, merr
	}
	ans := make([]*Certificate, 1)
	ans[0] = end_cert
	if end_cert.IsSelfSigned() {
		// We reached a self signed CA
		return ans, nil
	}
	// RECURSION!
	extra_path, err := store.build_path(issuer, max_depth-1)
	if extra_path == nil {
		// We failed to build the path
		if err.Code() == ERR_MAX_DEPTH_REACHED {
			return nil, err
		}
		return nil, NewMultiError("failure on recursion", err.Code(), nil, err)
	}
	// Add the recursion result
	ans = append(ans, extra_path...)
	return ans, nil
}

func (store *CAStore) add_CAs_in_zip_file(file *zip.File) bool {
	if file == nil {
		return false
	}

	// Open cert
	reader, err := file.Open()
	defer reader.Close()
	if err != nil {
		return false
	}

	// Get data
	raw, err := ioutil.ReadAll(reader)
	if err != nil {
		return false
	}

	// Parse it
	certs, _ := NewCertificateFromBytes(raw)

	// Add them all!
	for _, cert := range certs {
		store.add_ca_at_time(&cert, time.Now())
	}

	return true
}

func (store *CAStore) parse_CAs_zip(raw []byte, raw_len int64) error {
	if store.Debug {
		fmt.Println("[libICP-DEBUG] Adding all CAs from a zip file")
	}
	// Load zip
	zreader, err := zip.NewReader(bytes.NewReader(raw), raw_len)
	if err != nil {
		return err
	}

	// Try to add CAs until it is clear that no more are possible
	last_total := -1
	for i := 0; len(store.cas) != last_total && i < 10; i++ {
		last_total = len(store.cas)
		// For each file in the zip archive
		for _, file := range zreader.File {
			// Try to add its CA
			store.add_CAs_in_zip_file(file)
		}
	}

	return nil
}

// This function will attempt download all CAs from ALL_CAs_ZIP_URL. This runs regardless of CAStore.AutoDownload
func (store *CAStore) DownloadAllCAs() error {
	if store.Debug {
		fmt.Println("[libICP-DEBUG] Downloading all CAs from " + ALL_CAs_ZIP_URL)
	}
	buf, l, err := http_get(ALL_CAs_ZIP_URL)
	if err != nil {
		return err
	}
	return store.parse_CAs_zip(buf, l)
}

// Returns a copy
func (store CAStore) ListCRLs() map[string]bool {
	urls_set := make(map[string]bool)

	for _, ca := range store.cas {
		for _, url := range ca.ext_crl_distribution_points.URLs {
			urls_set[url] = true
		}
	}

	return urls_set
}
