package libICP

import (
	"encoding/pem"
	"io/ioutil"
	"reflect"
	"sync"
	"time"

	"github.com/OpenICP-BR/asn1"

	"github.com/LK4D4/trylock"
)

type Certificate struct {
	base                        certificate_pack
	Serial                      string
	Subject                     string
	SubjectMap                  map[string]string
	Issuer                      string
	IssuerMap                   map[string]string
	NotBefore                   time.Time
	NotAfter                    time.Time
	SubjectKeyId                string
	AuthorityKeyId              string
	ext_key_usage               ext_key_usage
	ext_basic_constraints       ext_basic_constraints
	ext_crl_distribution_points ext_crl_distribution_points
	// This is the crl published by this certificate, not the crl about this certificate
	crl certificate_list
	// These are calculated based on the CRL made by this cert issuer
	CRL_LastUpdate time.Time
	CRL_NextUpdate time.Time
	CRL_Status     CRLStatus
	CRL_LastCheck  time.Time
	CRL_LastError  CodedError
	crl_lock       *trylock.Mutex
}

// Accepts PEM, DER and a mix of both.
func NewCertificateFromFile(path string) ([]Certificate, []CodedError) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		merr := NewMultiError("failed to read certificate file", ERR_READ_FILE, nil, err)
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
			new_cert.init()
			_, merr := new_cert.load_from_der(block.Bytes)
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
		new_cert.init()
		rest, merr = new_cert.load_from_der(rest)
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
func new_CRL_from_file(path string) ([]certificate_list, []CodedError) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		merr := NewMultiError("failed to read CRL file", ERR_READ_FILE, nil, err)
		merr.SetParam("path", path)
		return nil, []CodedError{merr}
	}
	return new_CRL_from_bytes(dat)
}

// Accepts PEM, DER and a mix of both.
func new_CRL_from_bytes(raw []byte) ([]certificate_list, []CodedError) {
	var block *pem.Block
	crls := make([]certificate_list, 0)
	merrs := make([]CodedError, 0)

	// Try decoding all CRLs PEM blocks
	rest := raw
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "X509 CRL" {
			new_crl := certificate_list{}
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
		new_crl := certificate_list{}
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

func (cert *Certificate) load_from_der(data []byte) ([]byte, CodedError) {
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

func (cert *Certificate) init() {
	if cert.crl_lock == nil {
		cert.crl_lock = new(trylock.Mutex)
	}
}

// func (cert Certificate) ValidFor(usage CERT_USAGE) CodedError {
// }

func (cert Certificate) is_crl_outdated() bool {
	now := time.Now()
	return now.After(cert.CRL_NextUpdate) && !cert.CRL_NextUpdate.IsZero()
}

// Returns true if the subject is equal to the issuer.
func (cert Certificate) IsSelfSigned() bool {
	eq := reflect.DeepEqual(cert.SubjectMap, cert.IssuerMap)

	if eq || cert.SubjectKeyId == cert.AuthorityKeyId {
		return true
	}
	return false
}

// Returns true if this certificate is a certificate authority. This is checked via the following extensions: key usage and basic constraints extension. (see RFC 5280 Section 4.2.1.3 and Section 4.2.1.9, respectively)
func (cert Certificate) IsCA() bool {
	return cert.ext_key_usage.Exists && cert.ext_key_usage.KeyCertSign && cert.ext_basic_constraints.Exists && cert.ext_basic_constraints.CA
}

// This checks ONLY the digital signature and if the issuer is a CA (via the BasicConstraints and KeyUsage extensions). It will fail if any of those two extensions are not present.
//
// Possible errors are: ERR_UNKOWN_ALGORITHM, ERR_NOT_CA, ERR_PARSE_RSA_PUBKEY, ERR_BAD_SIGNATURE
func (cert Certificate) verify_signed_by(issuer Certificate) []CodedError {
	ans_errs := make([]CodedError, 0)

	// Check CA permission from issuer
	if !issuer.ext_key_usage.Exists || !issuer.ext_key_usage.KeyCertSign {
		merr := NewMultiError("issuer is not a certificate authority (Key Usage extension)", ERR_NOT_CA, nil)
		merr.SetParam("issuer.Subject", issuer.Subject)
		ans_errs = append(ans_errs, merr)
	}
	if !issuer.ext_basic_constraints.Exists || !issuer.ext_basic_constraints.CA {
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
	cerr := VerifySignaure(cert.base, pubkey)
	if err == nil {
		return nil
	}
	return []CodedError{cerr}
}

func (cert *Certificate) setCRL(crl certificate_list) {
	cert.crl = crl
	cert.CRL_LastCheck = cert.crl.TBSCertList.ThisUpdate
	cert.CRL_NextUpdate = cert.crl.TBSCertList.NextUpdate
}

func (cert *Certificate) finish_parsing() CodedError {
	cert.Serial = "0x" + cert.base.TBSCertificate.SerialNumber.Text(16)
	cert.Subject = cert.base.TBSCertificate.Subject.String()
	cert.SubjectMap = cert.base.TBSCertificate.Subject.Map()
	cert.Issuer = cert.base.TBSCertificate.Issuer.String()
	cert.IssuerMap = cert.base.TBSCertificate.Issuer.Map()
	cert.NotBefore = cert.base.TBSCertificate.Validity.NotBeforeTime
	cert.NotAfter = cert.base.TBSCertificate.Validity.NotAfterTime

	return cert.parse_extensions()
}

func (cert *Certificate) parse_extensions() CodedError {
	for _, ext := range cert.base.TBSCertificate.Extensions {
		id := ext.ExtnID
		switch {
		case id.Equal(idSubjectKeyIdentifier):
			ext_key_id := ext_subject_key_id{}
			if err := ext_key_id.FromExtension(ext); err != nil {
				return err
			}
			cert.SubjectKeyId = nice_hex(ext_key_id.KeyId)
		case id.Equal(idAuthorityKeyIdentifier):
			ext_key_id := ext_authority_key_id{}
			if err := ext_key_id.FromExtension(ext); err != nil {
				return err
			}
			cert.AuthorityKeyId = nice_hex(ext_key_id.KeyId)
		case id.Equal(idCeBasicConstraints):
			if err := cert.ext_basic_constraints.FromExtension(ext); err != nil {
				return err
			}
		case id.Equal(idCeKeyUsage):
			if err := cert.ext_key_usage.FromExtension(ext); err != nil {
				return err
			}
		case id.Equal(idCeCRLDistributionPoint):
			if err := cert.ext_crl_distribution_points.FromExtension(ext); err != nil {
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

func (cert *Certificate) check_against_issuer_crl(issuer *Certificate) {
	cert.CRL_LastCheck = issuer.crl.TBSCertList.ThisUpdate
	if issuer.CRL_LastError != nil || cert.CRL_LastCheck.IsZero() {
		cert.CRL_Status = CRL_UNSURE_OR_NOT_FOUND
		return
	}
	if issuer.crl_has_cert(*cert) {
		cert.CRL_Status = CRL_REVOKED
	} else {
		cert.CRL_Status = CRL_NOT_REVOKED
	}
}

func (cert Certificate) crl_has_cert(end_cert Certificate) bool {
	return cert.crl.TBSCertList.HasCert(end_cert.base.TBSCertificate.SerialNumber)
}

func (cert *Certificate) process_CRL(new_crl certificate_list) CodedError {
	// Verify signature
	pubkey, err := cert.base.TBSCertificate.SubjectPublicKeyInfo.RSAPubKey()
	if err != nil {
		return NewMultiError("failed to RSA parse public key", ERR_PARSE_RSA_PUBKEY, nil, err)
	}
	cerr := VerifySignaure(new_crl, pubkey)
	if cerr != nil {
		return cerr
	}

	// Check for critical extensions
	if ext := cert.crl.TBSCertList.HasCriticalExtension(); ext != nil {
		merr := NewMultiError("unsupported critical extension on CRL", ERR_UNSUPORTED_CRITICAL_EXTENSION, nil)
		merr.SetParam("ExtnId", ext)
		return merr
	}

	cert.setCRL(new_crl)
	return nil
}

func (cert *Certificate) download_crl(wg *sync.WaitGroup) {
	if !cert.crl_lock.TryLock() {
		wg.Done()
		return
	}
	defer cert.crl_lock.Unlock()

	var last_error CodedError
	for _, url := range cert.ext_crl_distribution_points.URLs {
		var buf []byte
		buf, _, last_error = http_get(url)
		if last_error != nil {
			continue
		}
		crls, _ := new_CRL_from_bytes(buf)
		for _, crl := range crls {
			last_error = cert.process_CRL(crl)
			if last_error == nil {
				break
			}
		}
	}
	cert.CRL_LastError = last_error
	wg.Done()
}
