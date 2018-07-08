package icp

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"reflect"
	"sync"
	"time"

	"github.com/LK4D4/trylock"
)

type CRLStatus int

const (
	CRL_UNSURE_OR_NOT_FOUND = 0
	// CRL_NOT_REVOKED is also used when the CA offers no means to check revocation status.
	CRL_NOT_REVOKED = 1
	CRL_REVOKED     = 2
)

type Certificate struct {
	base                        certificateT
	ext_subject_key_id          ExtSubjectKeyId
	ext_authority_key_id        ExtAuthorityKeyId
	ext_key_usage               ExtKeyUsage
	ext_basic_constraints       ExtBasicConstraints
	ext_crl_distribution_points ExtCRLDistributionPoints
	// The CRL this cert published, not the crl about this cert
	crl certificateListT
	// These are calculated based on the CRL made by this cert issuer
	crl_status     CRLStatus
	crl_last_check time.Time
	crl_lock       trylock.Mutex
	crl_last_error CodedError
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
			_, merr := new_cert.loadFromDER(block.Bytes)
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
		rest, merr = new_cert.loadFromDER(rest)
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

func (cert *Certificate) loadFromDER(data []byte) ([]byte, CodedError) {
	rest, err := asn1.Unmarshal(data, &cert.base)
	if err != nil {
		merr := NewMultiError("failed to parse DER certificate", ERR_PARSE_CERT, nil, err)
		merr.SetParam("raw-data", data)
		return rest, merr
	}

	if cerr := cert.finish_parsing(); cerr != nil {
		return rest, cerr
	}

	return rest, nil
}

func (cert Certificate) crl_this_update() time.Time {
	return cert.crl.TBSCertList.ThisUpdate
}

func (cert Certificate) crl_next_update() time.Time {
	return cert.crl.TBSCertList.NextUpdate
}

func (cert Certificate) NotBefore() time.Time {
	return cert.base.TBSCertificate.Validity.NotBeforeTime
}

func (cert Certificate) NotAfter() time.Time {
	return cert.base.TBSCertificate.Validity.NotAfterTime
}

func (cert Certificate) Subject() string {
	return cert.base.TBSCertificate.Subject.String()
}

func (cert Certificate) SubjectMap() map[string]string {
	return cert.base.TBSCertificate.Subject.Map()
}

func (cert Certificate) Issuer() string {
	return cert.base.TBSCertificate.Issuer.String()
}

func (cert Certificate) IssuerMap() map[string]string {
	return cert.base.TBSCertificate.Issuer.Map()
}

func (cert Certificate) Serial() string {
	return "0x" + cert.base.TBSCertificate.SerialNumber.Text(16)
}

func (cert Certificate) AuthorityKeyId() string {
	if !cert.ext_authority_key_id.Exists {
		return cert.Issuer()
	}
	return nice_hex(cert.ext_authority_key_id.KeyId)
}

func (cert Certificate) SubjectKeyId() string {
	if !cert.ext_subject_key_id.Exists {
		return cert.Subject()
	}
	return nice_hex(cert.ext_subject_key_id.KeyId)
}

func (cert Certificate) BasicConstraints() ExtBasicConstraints {
	return cert.ext_basic_constraints
}

func (cert Certificate) KeyUsage() ExtKeyUsage {
	return cert.ext_key_usage
}

func (cert Certificate) CRLDistributionPoints() ExtCRLDistributionPoints {
	return cert.ext_crl_distribution_points
}

func (cert Certificate) CRLStatus() (CRLStatus, time.Time) {
	return cert.crl_status, cert.crl_last_check
}

func (cert Certificate) is_crl_outdated(now time.Time) bool {
	return false
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
func (cert Certificate) verifySignedBy(issuer Certificate) []CodedError {
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
	pubkey, err := issuer.base.TBSCertificate.SubjectPublicKeyInfo.RSAPubKey()
	if err != nil {
		ans_errs = append(ans_errs, NewMultiError("failed to RSA parse public key", ERR_PARSE_RSA_PUBKEY, nil, err))
	}

	if len(ans_errs) > 0 {
		return ans_errs
	}

	// Verify signature
	cerr := verify_signaure(cert.base, pubkey)
	if err == nil {
		return nil
	}
	return []CodedError{cerr}
}

func (cert *Certificate) finish_parsing() CodedError {
	return cert.parse_extensions()
}

func (cert *Certificate) parse_extensions() CodedError {
	for _, ext := range cert.base.TBSCertificate.Extensions {
		id := ext.ExtnID
		switch {
		case id.Equal(idSubjectKeyIdentifier()):
			if err := cert.ext_subject_key_id.fromExtensionT(ext); err != nil {
				return err
			}
		case id.Equal(idAuthorityKeyIdentifier()):
			if err := cert.ext_authority_key_id.fromExtensionT(ext); err != nil {
				return err
			}
		case id.Equal(idCeBasicConstraints()):
			if err := cert.ext_basic_constraints.fromExtensionT(ext); err != nil {
				return err
			}
		case id.Equal(idCeKeyUsage()):
			if err := cert.ext_key_usage.fromExtensionT(ext); err != nil {
				return err
			}
		case id.Equal(idCeCRLDistributionPoint()):
			if err := cert.ext_crl_distribution_points.fromExtensionT(ext); err != nil {
				return err
			}
		default:
			if ext.Critical {
				merr := NewMultiError("unsupported critical extension", ERR_UNSUPORTED_CRITICAL_EXTENSION, nil)
				merr.SetParam("extension id", id)
				println("err")
				return merr
			}
		}
	}
	return nil
}

func (cert *Certificate) check_against_issuer_crl(issuer *Certificate) {
}

func (cert Certificate) CRLLastError() CodedError {
	return cert.crl_last_error
}

func (cert *Certificate) parse_crl(data []byte) CodedError {
	new_crl := certificateListT{}

	// Unmarshal data
	_, err := asn1.Unmarshal(data, &new_crl)
	if err != nil {
		merr := NewMultiError("failed to parse CRL", ERR_PARSE_CRL, nil, err)
		merr.SetParam("raw-data", data)
		return merr
	}

	// Verify signature
	pubkey, err := cert.base.TBSCertificate.SubjectPublicKeyInfo.RSAPubKey()
	if err != nil {
		return NewMultiError("failed to RSA parse public key", ERR_PARSE_RSA_PUBKEY, nil, err)
	}
	fmt.Println(cert.SubjectMap()["CN"])
	fmt.Println(new_crl.TBSCertList.Issuer.Map()["CN"])
	cerr := verify_signaure(new_crl, pubkey)
	if cerr != nil {
		fmt.Println(cerr.Error())
		return cerr
	}
	cert.crl = new_crl
	return nil
}

func (cert *Certificate) download_crl(wg *sync.WaitGroup) {
	defer wg.Done()

	if !cert.crl_lock.TryLock() {
		return
	}
	defer cert.crl_lock.Unlock()

	var last_error CodedError
	for _, url := range cert.CRLDistributionPoints().URLs {
		var buf []byte
		buf, _, last_error = http_get(url)
		if last_error != nil {
			continue
		}
		last_error = cert.parse_crl(buf)
		if last_error == nil {
			break
		}
	}
	cert.crl_last_error = last_error
}
