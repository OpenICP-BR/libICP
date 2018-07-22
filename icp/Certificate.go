package icp

import (
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"reflect"
	"sync"
	"time"

	"github.com/gjvnq/asn1"

	"github.com/LK4D4/trylock"
)

type Certificate struct {
	Base                     CertificatePack
	ExtSubjectKeyId          ExtSubjectKeyId
	ExtAuthorityKeyId        ExtAuthorityKeyId
	ExtKeyUsage              ExtKeyUsage
	ExtBasicConstraints      ExtBasicConstraints
	ExtCRLDistributionPoints ExtCRLDistributionPoints
	// The CRL this cert published, not the crl about this cert
	CRL CertificateList
	// These are calculated based on the CRL made by this cert issuer
	CRL_Status    CRLStatus
	CRL_LastCheck time.Time
	CRL_Lock      trylock.Mutex
	CRL_LastError CodedError
}

// Accepts PEM, DER and a mix of both.
func NewCertificateFromFile(path string) ([]Certificate, []CodedError) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		merr := NewMultiError("failed to read certificate file", ERR_READ_CERT_FILE, nil, err)
		merr.SetParam("path", path)
		return nil, []CodedError{merr}
	}
	return NewCertificateFromBytes(dat)
}

// Accepts PEM, DER and a mix of both.
func NewCertificateFromBytes(raw []byte) ([]Certificate, []CodedError) {
	var block *pem.Block
	certs := make([]Certificate, 0)
	merrs := make([]CodedError, 0)

	// Try decoding all certificate PEM blocks
	rest := raw
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			new_cert := Certificate{}
			_, merr := new_cert.LoadFromDER(block.Bytes)
			certs = append(certs, new_cert)
			merrs = append(merrs, merr)
		}
	}

	// Try decoding the rest as DER certificates
	for {
		var merr CodedError
		// Finished reading file?
		if rest == nil || len(rest) < 42 {
			break
		}
		new_cert := Certificate{}
		rest, merr = new_cert.LoadFromDER(rest)
		certs = append(certs, new_cert)
		merrs = append(merrs, merr)
	}

	// Avoid returining an array of nils.
	for _, merr := range merrs {
		if merr != nil {
			return certs, merrs
		}
	}
	return certs, nil
}

// Accepts PEM, DER and a mix of both.
func NewCRLFromFile(path string) ([]CertificateList, []CodedError) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		merr := NewMultiError("failed to read CRL file", ERR_READ_CERT_FILE, nil, err)
		merr.SetParam("path", path)
		return nil, []CodedError{merr}
	}
	return NewCRLFromBytes(dat)
}

// Accepts PEM, DER and a mix of both.
func NewCRLFromBytes(raw []byte) ([]CertificateList, []CodedError) {
	var block *pem.Block
	crls := make([]CertificateList, 0)
	merrs := make([]CodedError, 0)

	// Try decoding all CRLs PEM blocks
	rest := raw
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "X509 CRL" {
			new_crl := CertificateList{}
			_, merr := new_crl.LoadFromDER(block.Bytes)
			crls = append(crls, new_crl)
			merrs = append(merrs, merr)
		}
	}

	// Try decoding the rest as DER CRL
	for {
		var merr CodedError
		// Finished reading file?
		if rest == nil || len(rest) < 42 {
			break
		}
		new_crl := CertificateList{}
		rest, merr = new_crl.LoadFromDER(rest)
		crls = append(crls, new_crl)
		merrs = append(merrs, merr)
	}

	// Avoid returining an array of nils.
	for _, merr := range merrs {
		if merr != nil {
			return crls, merrs
		}
	}
	return crls, nil
}

func (cert *Certificate) LoadFromDER(data []byte) ([]byte, CodedError) {
	rest, err := asn1.Unmarshal(data, &cert.Base)
	if err != nil {
		merr := NewMultiError("failed to parse DER certificate", ERR_PARSE_CERT, nil, err)
		merr.SetParam("raw-data", data)
		return rest, merr
	}

	if cerr := cert.FinishParsing(); cerr != nil {
		return rest, cerr
	}

	return rest, nil
}

func (cert Certificate) CRLThisUpdate() time.Time {
	return cert.CRL.TBSCertList.ThisUpdate
}

func (cert Certificate) CRLNextUpdate() time.Time {
	return cert.CRL.TBSCertList.NextUpdate
}

func (cert Certificate) NotBefore() time.Time {
	return cert.Base.TBSCertificate.Validity.NotBeforeTime
}

func (cert Certificate) NotAfter() time.Time {
	return cert.Base.TBSCertificate.Validity.NotAfterTime
}

func (cert Certificate) Subject() string {
	return cert.Base.TBSCertificate.Subject.String()
}

func (cert Certificate) SubjectMap() map[string]string {
	return cert.Base.TBSCertificate.Subject.Map()
}

func (cert Certificate) Issuer() string {
	return cert.Base.TBSCertificate.Issuer.String()
}

func (cert Certificate) IssuerMap() map[string]string {
	return cert.Base.TBSCertificate.Issuer.Map()
}

func (cert Certificate) serial_as_big_int() *big.Int {
	return cert.Base.TBSCertificate.SerialNumber
}

func (cert Certificate) Serial() string {
	return "0x" + cert.Base.TBSCertificate.SerialNumber.Text(16)
}

func (cert Certificate) AuthorityKeyId() string {
	if !cert.ExtAuthorityKeyId.Exists {
		return cert.Issuer()
	}
	return NiceHex(cert.ExtAuthorityKeyId.KeyId)
}

func (cert Certificate) SubjectKeyId() string {
	if !cert.ExtSubjectKeyId.Exists {
		return cert.Subject()
	}
	return NiceHex(cert.ExtSubjectKeyId.KeyId)
}

func (cert Certificate) BasicConstraints() ExtBasicConstraints {
	return cert.ExtBasicConstraints
}

func (cert Certificate) KeyUsage() ExtKeyUsage {
	return cert.ExtKeyUsage
}

func (cert Certificate) CRLDistributionPoints() ExtCRLDistributionPoints {
	return cert.ExtCRLDistributionPoints
}

func (cert Certificate) CRLStatus() CRLStatus {
	return cert.CRL_Status
}

func (cert Certificate) CRLLastCheck() time.Time {
	return cert.CRL_LastCheck
}

func (cert Certificate) IsCRLOutdated(now time.Time) bool {
	return now.After(cert.CRLNextUpdate()) && !cert.CRLNextUpdate().IsZero()
}

// Returns true if the subject is equal to the issuer.
func (cert Certificate) IsSelfSigned() bool {
	eq := reflect.DeepEqual(cert.SubjectMap(), cert.IssuerMap())

	if eq || cert.SubjectKeyId() == cert.AuthorityKeyId() {
		return true
	}
	return false
}

// Returns true if this certificate is a certificate authority. This is checked via the following extensions: key usage and basic constraints extension. (see RFC 5280 Section 4.2.1.3 and Section 4.2.1.9, respectively)
func (cert Certificate) IsCA() bool {
	return cert.KeyUsage().Exists && cert.KeyUsage().KeyCertSign && cert.BasicConstraints().Exists && cert.BasicConstraints().CA
}

// This checks ONLY the digital signature and if the issuer is a CA (via the BasicConstraints and KeyUsage extensions). It will fail if any of those two extensions are not present.
//
// Possible errors are: ERR_UNKOWN_ALGORITHM, ERR_NOT_CA, ERR_PARSE_RSA_PUBKEY, ERR_BAD_SIGNATURE
func (cert Certificate) VerifySignedBy(issuer Certificate) []CodedError {
	ans_errs := make([]CodedError, 0)

	// Check CA permission from issuer
	if !issuer.KeyUsage().Exists || !issuer.KeyUsage().KeyCertSign {
		merr := NewMultiError("issuer is not a certificate authority (Key Usage extension)", ERR_NOT_CA, nil)
		merr.SetParam("issuer.Subject", issuer.Subject)
		ans_errs = append(ans_errs, merr)
	}
	if !issuer.BasicConstraints().Exists || !issuer.BasicConstraints().CA {
		merr := NewMultiError("issuer is not a certificate authority (Basic Constraints extension)", ERR_NOT_CA, nil)
		merr.SetParam("issuer.Subject", issuer.Subject)
		ans_errs = append(ans_errs, merr)
	}

	// Get key
	pubkey, err := issuer.Base.TBSCertificate.SubjectPublicKeyInfo.RSAPubKey()
	if err != nil {
		ans_errs = append(ans_errs, NewMultiError("failed to RSA parse public key", ERR_PARSE_RSA_PUBKEY, nil, err))
	}

	if len(ans_errs) > 0 {
		return ans_errs
	}

	// Verify signature
	cerr := VerifySignaure(cert.Base, pubkey)
	if err == nil {
		return nil
	}
	return []CodedError{cerr}
}

func (cert *Certificate) FinishParsing() CodedError {
	return cert.ParseExtensions()
}

func (cert *Certificate) ParseExtensions() CodedError {
	for _, ext := range cert.Base.TBSCertificate.Extensions {
		id := ext.ExtnID
		switch {
		case id.Equal(IdSubjectKeyIdentifier()):
			if err := cert.ExtSubjectKeyId.FromExtension(ext); err != nil {
				return err
			}
		case id.Equal(IdAuthorityKeyIdentifier()):
			if err := cert.ExtAuthorityKeyId.FromExtension(ext); err != nil {
				return err
			}
		case id.Equal(IdCeBasicConstraints()):
			if err := cert.ExtBasicConstraints.FromExtension(ext); err != nil {
				return err
			}
		case id.Equal(IdCeKeyUsage()):
			if err := cert.ExtKeyUsage.FromExtension(ext); err != nil {
				return err
			}
		case id.Equal(IdCeCRLDistributionPoint()):
			if err := cert.ExtCRLDistributionPoints.FromExtension(ext); err != nil {
				return err
			}
		default:
			if ext.Critical {
				merr := NewMultiError("unsupported critical extension", ERR_UNSUPORTED_CRITICAL_EXTENSION, nil)
				merr.SetParam("extension id", id)
				return merr
			}
		}
	}
	return nil
}

func (cert *Certificate) CheckAgainstIssuerCRL(issuer *Certificate) {
	cert.CRL_LastCheck = issuer.CRLThisUpdate()
	if issuer.CRL_LastError != nil || cert.CRL_LastCheck.IsZero() {
		cert.CRL_Status = CRL_UNSURE_OR_NOT_FOUND
		return
	}
	if issuer.CRLHasCert(*cert) {
		cert.CRL_Status = CRL_REVOKED
	} else {
		cert.CRL_Status = CRL_NOT_REVOKED
	}
}

func (cert Certificate) CRLLastError() CodedError {
	return cert.CRL_LastError
}

func (cert Certificate) CRLHasCert(end_cert Certificate) bool {
	return cert.CRL.TBSCertList.HasCert(end_cert.serial_as_big_int())
}

func (cert *Certificate) ProcessCRL(new_crl CertificateList) CodedError {
	// Verify signature
	pubkey, err := cert.Base.TBSCertificate.SubjectPublicKeyInfo.RSAPubKey()
	if err != nil {
		return NewMultiError("failed to RSA parse public key", ERR_PARSE_RSA_PUBKEY, nil, err)
	}
	cerr := VerifySignaure(new_crl, pubkey)
	if cerr != nil {
		return cerr
	}

	// Check for critical extensions
	if ext := cert.CRL.TBSCertList.HasCriticalExtension(); ext != nil {
		merr := NewMultiError("unsupported critical extension on CRL", ERR_UNSUPORTED_CRITICAL_EXTENSION, nil)
		merr.SetParam("ExtnId", ext)
		return merr
	}

	cert.CRL = new_crl
	return nil
}

func (cert *Certificate) DownloadCRL(wg *sync.WaitGroup) {
	if !cert.CRL_Lock.TryLock() {
		wg.Done()
		return
	}
	defer cert.CRL_Lock.Unlock()

	var last_error CodedError
	for _, url := range cert.CRLDistributionPoints().URLs {
		var buf []byte
		buf, _, last_error = HTTPGet(url)
		if last_error != nil {
			continue
		}
		crls, _ := NewCRLFromBytes(buf)
		for _, crl := range crls {
			last_error = cert.ProcessCRL(crl)
			if last_error == nil {
				break
			}
		}
	}
	cert.CRL_LastError = last_error
	wg.Done()
}
