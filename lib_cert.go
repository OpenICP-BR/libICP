package icp

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
	"time"
)

type Certificate struct {
	base           certificateT
	Serial         string
	Issuer         string
	IssuerMap      map[string]string
	Subject        string
	SubjectMap     map[string]string
	SubjectKeyID   string
	AuthorityKeyID string
	NotBefore      time.Time
	NotAfter       time.Time
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
			ok, _, merr := new_cert.loadFromDER(block.Bytes)
			if !ok {
				merrs = append(merrs, merr)
			} else {
				certs = append(certs, new_cert)
			}
		}
	}

	// Try decoding the rest as DER certificates
	for {
		var ok bool
		var merr CodedError
		// Finished reading file?
		if rest == nil || len(rest) < 42 {
			break
		}
		new_cert := Certificate{}
		ok, rest, merr = new_cert.loadFromDER(rest)
		if ok {
			certs = append(certs, new_cert)
		} else {
			merrs = append(merrs, merr)
		}
	}

	if len(merrs) == 0 {
		merrs = nil
	}
	return certs, merrs
}

func (cert *Certificate) loadFromDER(data []byte) (bool, []byte, CodedError) {
	rest, err := asn1.Unmarshal(data, &cert.base)
	if err != nil {
		merr := NewMultiError("failed to parse DER certificate", ERR_PARSE_CERT, nil, err)
		merr.SetParam("raw-data", data)
		return false, rest, merr
	}

	cert.finishParsing()

	return true, rest, nil
}

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

func (cert Certificate) verifySignedBy(issuer Certificate) (bool, CodedError) {
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
		return false, merr
	}

	// Write raw value
	tbs_hasher.Write(cert.base.TBSCertificate.RawContent)
	hash_ans := make([]byte, 0)
	hash_ans = tbs_hasher.Sum(hash_ans)

	// Get key and signature
	sig := cert.base.Signature.Bytes
	pubkey, err := issuer.base.TBSCertificate.SubjectPublicKeyInfo.RSAPubKey()
	if err != nil {
		return false, NewMultiError("failed to parse public key", ERR_PARSE_RSA_PUBKEY, nil, err)
	}

	// Verify signature
	err = rsa.VerifyPKCS1v15(&pubkey, tbs_hash_alg, hash_ans, sig)
	if err != nil {
		fmt.Println(err)
		return false, NewMultiError("failed to verify signature", ERR_BAD_SIGNATURE, nil, err)
	}

	return true, nil
}

func (cert *Certificate) finishParsing() {
	cert.Serial = "0x" + cert.base.TBSCertificate.SerialNumber.Text(16)
	cert.Issuer = cert.base.TBSCertificate.Issuer.String()
	cert.IssuerMap = cert.base.TBSCertificate.Issuer.Map()
	cert.Subject = cert.base.TBSCertificate.Subject.String()
	cert.SubjectMap = cert.base.TBSCertificate.Subject.Map()
	// Just a hack to prevent some problems
	cert.SubjectKeyID = cert.Subject
	cert.AuthorityKeyID = cert.Issuer
	// Look for SubjectKeyID and AuthorityKeyID
	for _, ext := range cert.base.TBSCertificate.Extensions {
		if ext.ExtnID.Equal(idSubjectKeyIdentifier()) {
			cert.SubjectKeyID = nice_hex(ext.ExtnValue)
		}
		if ext.ExtnID.Equal(idAuthorityKeyIdentifier()) {
			cert.AuthorityKeyID = nice_hex(ext.ExtnValue)
		}
	}
	// Get validity
	cert.NotBefore = cert.base.TBSCertificate.Validity.NotBeforeTime
	cert.NotAfter = cert.base.TBSCertificate.Validity.NotAfterTime
}
