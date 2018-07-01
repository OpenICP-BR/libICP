package icp

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/pem"
	"hash"
	"io/ioutil"
	"time"
)

type Certificate struct {
	base                     certificateT
	Serial                   string
	Issuer                   string
	IssuerMap                map[string]string
	Subject                  string
	SubjectMap               map[string]string
	SubjectKeyID             string
	AuthorityKeyID           string
	NotBefore                time.Time
	NotAfter                 time.Time
	ExtKeyUsage              ExtKeyUsage
	ExtBasicConstraints      ExtBasicConstraints
	ExtCRLDistributionPoints ExtCRLDistributionPoints
}

// Accepts PEM, DER and a mix of both.
func NewCertificateFromFile(path string) ([]Certificate, CodedError) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		merr := NewMultiError("failed to read certificate file", ERR_READ_CERT_FILE, nil, err)
		merr.SetParam("path", path)
		return nil, merr
	}
	certs, errs := NewCertificateFromBytes(dat)
	if errs != nil {
		merr := NewMultiError("failed to parse some certificates", ERR_PARSE_CERT, nil, errs)
		merr.SetParam("path", path)
		return certs, merr
	}
	return certs, nil
}

func firstCert(certs []Certificate, stuff []CodedError) Certificate {
	return certs[0]
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

	if cerr := cert.finishParsing(); cerr != nil {
		return rest, cerr
	}

	return rest, nil
}

// Returns true if the subject is equal to the issuer.
func (cert Certificate) SelfSigned() bool {
	if cert.Subject == cert.Issuer || cert.SubjectKeyID == cert.AuthorityKeyID {
		return true
	}
	if len(cert.SubjectMap) != len(cert.IssuerMap) {
		return false
	}
	for k, v := range cert.SubjectMap {
		if v != cert.IssuerMap[k] {
			return false
		}
	}
	return true
}

// Returns true if this certificate is a certificate authority. This is checked via the basic constraints extension. (see RFC 5280 Section 4.2.1.9 Page 38)
func (cert Certificate) IsCA() bool {
	return cert.ExtBasicConstraints.CA
}

func (cert Certificate) verifySignedBy(issuer Certificate) []CodedError {
	ans_errs := make([]CodedError, 0)
	// Check algorithm
	alg := cert.base.SignatureAlgorithm.Algorithm
	var tbs_hasher hash.Hash
	var tbs_hash_alg crypto.Hash
	switch {
	case alg.Equal(idSha1WithRSAEncryption()):
		tbs_hasher = sha1.New()
		tbs_hash_alg = crypto.SHA1
	case alg.Equal(idSha256WithRSAEncryption()):
		tbs_hasher = sha256.New()
		tbs_hash_alg = crypto.SHA256
	case alg.Equal(idSha384WithRSAEncryption()):
		tbs_hasher = sha512.New384()
		tbs_hash_alg = crypto.SHA384
	case alg.Equal(idSha512WithRSAEncryption()):
		tbs_hasher = sha512.New()
		tbs_hash_alg = crypto.SHA512
	default:
		merr := NewMultiError("unknown algorithm", ERR_UNKOWN_ALGORITHM, nil)
		merr.SetParam("algorithm", alg)
		ans_errs = append(ans_errs, merr)
		return ans_errs
	}

	// Check CA permission from issuer
	if issuer.ExtKeyUsage.Exists && !issuer.ExtKeyUsage.KeyCertSign {
		ans_errs = append(ans_errs, NewMultiError("issuer is not a certificate authority (Key Usage extension)", ERR_NOT_CA, nil))
	}
	if issuer.ExtBasicConstraints.Exists && !issuer.ExtBasicConstraints.CA {
		ans_errs = append(ans_errs, NewMultiError("issuer is not a certificate authority (Basic Constraints extension)", ERR_NOT_CA, nil))
	}

	// Write raw value
	tbs_hasher.Write(cert.base.TBSCertificate.RawContent)
	hash_ans := make([]byte, 0)
	hash_ans = tbs_hasher.Sum(hash_ans)

	// Get key and signature
	sig := cert.base.Signature.Bytes
	pubkey, err := issuer.base.TBSCertificate.SubjectPublicKeyInfo.RSAPubKey()
	if err != nil {
		ans_errs = append(ans_errs, NewMultiError("failed to parse public key", ERR_PARSE_RSA_PUBKEY, nil, err))
	}
	if len(ans_errs) > 0 {
		return ans_errs
	}

	// Verify signature
	err = rsa.VerifyPKCS1v15(&pubkey, tbs_hash_alg, hash_ans, sig)
	if err != nil {
		return []CodedError{NewMultiError("failed to verify signature", ERR_BAD_SIGNATURE, nil, err)}

	}
	return nil
}

func (cert *Certificate) finishParsing() CodedError {
	cert.Serial = "0x" + cert.base.TBSCertificate.SerialNumber.Text(16)
	cert.Issuer = cert.base.TBSCertificate.Issuer.String()
	cert.IssuerMap = cert.base.TBSCertificate.Issuer.Map()
	cert.Subject = cert.base.TBSCertificate.Subject.String()
	cert.SubjectMap = cert.base.TBSCertificate.Subject.Map()
	// Get validity
	cert.NotBefore = cert.base.TBSCertificate.Validity.NotBeforeTime
	cert.NotAfter = cert.base.TBSCertificate.Validity.NotAfterTime
	// Just a hack to prevent some problems
	cert.SubjectKeyID = cert.Subject
	cert.AuthorityKeyID = cert.Issuer
	// Look for SubjectKeyID, AuthorityKeyID and other extensions
	return cert.parseExtensions()
}

func (cert *Certificate) parseExtensions() CodedError {
	// Look for SubjectKeyID and AuthorityKeyID
	for _, ext := range cert.base.TBSCertificate.Extensions {
		id := ext.ExtnID
		val := ext.ExtnValue
		switch {
		case id.Equal(idSubjectKeyIdentifier()):
			cert.SubjectKeyID = nice_hex(val)
		case id.Equal(idAuthorityKeyIdentifier()):
			cert.AuthorityKeyID = nice_hex(val)
		case id.Equal(idCeBasicConstraints()):
			if err := cert.ExtBasicConstraints.fromExtensionT(ext); err != nil {
				return err
			}
		case id.Equal(idCeKeyUsage()):
			if err := cert.ExtKeyUsage.fromExtensionT(ext); err != nil {
				return err
			}
		case id.Equal(idCeCRLDistributionPoint()):
			if err := cert.ExtCRLDistributionPoints.fromExtensionT(ext); err != nil {
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
