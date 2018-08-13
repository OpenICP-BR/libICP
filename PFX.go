package libICP

import (
	"crypto/rsa"
	"io/ioutil"
	"math/big"
	"time"
)

// Represents a .p12/.pfx file containing a public certificate and a private key which is usually encrypted.
//
// Only password privacy mode and password integrity mode are supported.
type PFX struct {
	base pfx_raw

	Cert Certificate
	Key  *rsa.PrivateKey
}

// Generates a new root CA with subject and issuer TESTING_ROOT_CA_SUBJECT
func NewRootCA(not_before, not_after time.Time) (PFX, CodedError) {
	name := nameT{
		[]atv{atv{Type: idCountryName, Value: "BR"}},
		[]atv{atv{Type: idOrganizationName, Value: "Fake ICP-Brasil"}},
		[]atv{atv{Type: idOrganizationalUnitName, Value: "Apenas para testes - SEM VALOR LEGAL"}},
		[]atv{atv{Type: idCommonName, Value: "Autoridade Certificadora Raiz de Testes - SEM VALOR LEGAL"}},
	}
	return NewCertAndKey(name, name, big.NewInt(1), not_before, not_after)
}

func NewCertAndKey(subject, issuer nameT, serial *big.Int, not_before, not_after time.Time) (pfx PFX, cerr CodedError) {
	var pair pair_alg_pub_key

	// Generate key pair
	pfx.Key, pair, cerr = new_rsa_key(1024)
	if cerr != nil {
		return
	}

	// Set data
	pfx.Cert.base.TBSCertificate.Issuer = issuer
	pfx.Cert.base.TBSCertificate.Subject = subject
	pfx.Cert.base.TBSCertificate.Issuer = issuer
	pfx.Cert.base.TBSCertificate.SerialNumber = serial
	pfx.Cert.base.TBSCertificate.Validity.NotBeforeTime = not_before
	pfx.Cert.base.TBSCertificate.Validity.NotAfterTime = not_after
	pfx.Cert.base.TBSCertificate.Signature.Algorithm = idSha512WithRSAEncryption
	pfx.Cert.base.SignatureAlgorithm.Algorithm = idSha512WithRSAEncryption
	pfx.Cert.base.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm = idSha512WithRSAEncryption
	pfx.Cert.base.TBSCertificate.SubjectPublicKeyInfo.PublicKey = pair.PublicKey
	pfx.Cert.base.TBSCertificate.SetAppropriateVersion()
	pfx.Cert.finish_parsing()

	// Marshal certificate
	cerr = pfx.Cert.base.MarshalCert()
	if cerr != nil {
		return
	}

	// Sign certificate
	cerr = Sign(&pfx.Cert.base, pfx.Key)
	return
}

// Saves the certificate to an unencrypted DER file. The private key is NOT included in the output.
func (pfx PFX) SaveCertToFile(path string) CodedError {
	// Marshal pack
	cerr := pfx.Cert.base.MarshalPack()
	if cerr != nil {
		return cerr
	}

	err := ioutil.WriteFile(path, pfx.Cert.base.RawContent, 0644)
	if err != nil {
		return NewMultiError("failed to write to file", ERR_FAILED_TO_WRITE_FILE, nil, err)
	}

	return nil
}

// Saves the certificate and the private key to a DER file.
func (pfx PFX) SaveToFile(path, password string) CodedError {
	// Marshal
	cerr := pfx.base.Marshal(password, pfx.Cert.base, pfx.Key)
	if cerr != nil {
		return cerr
	}

	err := ioutil.WriteFile(path, pfx.base.RawContent, 0644)
	if err != nil {
		return NewMultiError("failed to write to file", ERR_FAILED_TO_WRITE_FILE, nil, err)
	}

	return nil
}
