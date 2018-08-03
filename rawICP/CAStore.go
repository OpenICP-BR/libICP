package rawICP

import (
	"archive/zip"
	"bytes"
	"io/ioutil"
	"sync"
	"time"
)

const TESTING_ROOT_CA_SUBJECT = "C=BR/O=Fake-ICP-Brasil/OU=Apenas para testes - SEM VALOR LEGAL/CN=Autoridade Certificadora Raiz de Testes - SEM VALOR LEGAL"

// The lack of HTTPS is not a security problem because the root CAs are embedded in libICP and all CAs are checked against them. (see file `data.go`)
const ALL_CAs_ZIP_URL = "http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip"

type CAStore struct {
	// If true, it will attempt to download missing CAs and CRLs
	AutoDownload bool
	CAs          map[string]*Certificate
	inited       bool
	Wg           sync.WaitGroup
}

// Calls CAStore.Init() for you.
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
	store.CAs = make(map[string]*Certificate)
	for i, _ := range certs {
		store.DirectAddCA(&certs[i])
	}
	store.inited = true
}

// For now, this functions verifies: validity, integrity, propper chain of certification.
//
// Some of the error codes this may return are: ERR_NOT_BEFORE_DATE, ERR_NOT_AFTER_DATE, ERR_BAD_SIGNATURE, ERR_ISSUER_NOT_FOUND, ERR_MAX_DEPTH_REACHED
func (store CAStore) VerifyCertAt(cert_to_verify *Certificate, now time.Time) ([]*Certificate, []CodedError, []CodedWarning) {
	ans_errs := make([]CodedError, 0)
	ans_warns := make([]CodedWarning, 0)
	// Get certification path
	path, err := store.BuildPath(cert_to_verify, PATH_BUILDING_MAX_DEPTH)
	if err != nil {
		ans_errs = append(ans_errs, err)
		return nil, ans_errs, nil
	}
	last_ca_max_ca_i := -1
	last_ca_subj := ""

	// Check each certificate
	for i, cert := range path {
		if !now.After(cert.NotBefore()) {
			merr := NewMultiError("certificate not yet valid", ERR_NOT_BEFORE_DATE, nil)
			merr.SetParam("cert.NotBefore", cert.NotBefore())
			merr.SetParam("now", now)
			merr.SetParam("cert.Subject", cert.Subject())
			ans_errs = append(ans_errs, merr)
		}
		if !now.Before(cert.NotAfter()) {
			merr := NewMultiError("certificate has expired", ERR_NOT_AFTER_DATE, nil)
			merr.SetParam("cert.NotAfter", cert.NotAfter())
			merr.SetParam("now", now)
			merr.SetParam("cert.Subject", cert.Subject())
			ans_errs = append(ans_errs, merr)
		}

		// Take care of the basic constraints extension
		if cert.IsCA() && cert.BasicConstraints().Exists && cert.BasicConstraints().CA && cert.BasicConstraints().PathLen != 0 {
			new_max_i := i + cert.BasicConstraints().PathLen
			if last_ca_max_ca_i > 0 && last_ca_max_ca_i > new_max_i {
				last_ca_subj = cert.Subject()
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
		if errs := cert.VerifySignedBy(*issuer); errs != nil {
			ans_errs = append(ans_errs, errs...)
		}

		if issuer.IsCRLOutdated(now) && store.AutoDownload {
			go issuer.DownloadCRL(&store.Wg)
		}
		cert.CheckAgainstIssuerCRL(issuer)

		status := cert.CRLStatus()
		if status == CRL_REVOKED {
			merr := NewMultiError("certificate revoked (source: CRL)", ERR_REVOKED, nil)
			merr.SetParam("cert.Subject", cert.Subject)
			merr.SetParam("cert.Issuer", cert.Issuer)
			merr.SetParam("crl.ThisUpdate", issuer.CRLThisUpdate())
			ans_errs = append(ans_errs, merr)
		}
		if status == CRL_UNSURE_OR_NOT_FOUND {
			merr := NewMultiError("certificate possibly revoked", ERR_UNKOWN_REVOCATION_STATUS, nil)
			merr.SetParam("cert.Subject", cert.Subject)
			merr.SetParam("cert.Issuer", cert.Issuer)
			merr.SetParam("crl.ThisUpdate", issuer.CRLThisUpdate())
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
	if cert.Subject() != cert.Issuer() || cert.Subject() != TESTING_ROOT_CA_SUBJECT {
		merr := NewMultiError("AddTestingRootCA REQUIRES the testing CA to have a specific subject and issuer", ERR_TEST_CA_IMPROPPER_NAME, nil)
		merr.SetParam("expected-value", TESTING_ROOT_CA_SUBJECT)
		merr.SetParam("actual-subject", cert.Subject)
		merr.SetParam("actual-issuer", cert.Issuer)
		return []CodedError{merr}
	}

	store.DirectAddCA(cert)

	return nil
}

// Adds a new CA (certificate authority) if, and only if, it is valid when check against the existing CAs.
func (store *CAStore) AddCAatTime(cert *Certificate, now time.Time) []CodedError {
	if !cert.IsCA() {
		return []CodedError{NewMultiError("certificate is not a certificate authority", ERR_NOT_CA, nil)}
	}
	if _, errs, _ := store.VerifyCertAt(cert, now); errs != nil {
		return errs
	}
	store.DirectAddCA(cert)
	return nil
}

func (store *CAStore) DirectAddCA(cert *Certificate) {
	if cert == nil {
		return
	}

	// Attempt to download CRL
	if store.AutoDownload {
		println("Downloading CRL for", cert.SubjectMap()["CN"])
		store.Wg.Add(1)
		go cert.DownloadCRL(&store.Wg)
		store.Wg.Add(1)
		go cert.DownloadCRL(&store.Wg)
	}

	store.CAs[cert.SubjectKeyId()] = cert
	store.CAs[cert.Subject()] = cert
}

func (store CAStore) WaitDownloads() {
	store.Wg.Wait()
}

const PATH_BUILDING_MAX_DEPTH = 16

func (store CAStore) BuildPath(end_cert *Certificate, max_depth int) ([]*Certificate, CodedError) {
	if max_depth < 0 {
		merr := NewMultiError("reached maximum depth", ERR_MAX_DEPTH_REACHED, nil)
		merr.SetParam("SubjectKeyID", end_cert.SubjectKeyId())
		merr.SetParam("AuthorityKeyID", end_cert.AuthorityKeyId())
		return nil, merr
	}

	issuer, ok := store.CAs[end_cert.AuthorityKeyId()]
	if !ok {
		// Try again
		issuer, ok = store.CAs[end_cert.Issuer()]
	}
	if !ok {
		merr := NewMultiError("issuer not found", ERR_ISSUER_NOT_FOUND, nil)
		merr.SetParam("AuthorityKeyID", end_cert.AuthorityKeyId())
		return nil, merr
	}
	ans := make([]*Certificate, 1)
	ans[0] = end_cert
	if end_cert.IsSelfSigned() {
		// We reached a self signed CA
		return ans, nil
	}
	// RECURSION!
	extra_path, err := store.BuildPath(issuer, max_depth-1)
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

func (store *CAStore) AddCAsInZipFile(file *zip.File) bool {
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
		store.AddCAatTime(&cert, time.Now())
	}

	return true
}

func (store *CAStore) ParseCAsZip(raw []byte, raw_len int64) error {
	// Load zip
	zreader, err := zip.NewReader(bytes.NewReader(raw), raw_len)
	if err != nil {
		return err
	}

	// Try to add CAs until it is clear that no more are possible
	last_total := -1
	for i := 0; len(store.CAs) != last_total && i < 10; i++ {
		last_total = len(store.CAs)
		// For each file in the zip archive
		for _, file := range zreader.File {
			// Try to add its CA
			store.AddCAsInZipFile(file)
		}
	}

	return nil
}

// This function will attempt download all CAs from ALL_CAs_ZIP_URL. This runs regardless of CAStore.AutoDownload
func (store *CAStore) DownloadAllCAs() error {
	buf, l, err := HTTPGet(ALL_CAs_ZIP_URL)
	if err != nil {
		return err
	}
	return store.ParseCAsZip(buf, l)
}

func (store CAStore) ListCRLs() map[string]bool {
	urls_set := make(map[string]bool)

	for _, ca := range store.CAs {
		for _, url := range ca.CRLDistributionPoints().URLs {
			urls_set[url] = true
		}
	}

	return urls_set
}
