package libICP

import (
	"crypto/rsa"
	"io/ioutil"
	"math/big"
	"time"
)

type P12 struct {
	// base p12_raw

	Cert Certificate
	Key  *rsa.PrivateKey
}

// Generates a new root ca with subject and issuer TESTING_ROOT_CA_SUBJECT
func NewRootCA(not_before, not_after time.Time) (P12, CodedError) {
	name := nameT{
		[]atv{atv{Type: idCountryName, Value: "BR"}},
		[]atv{atv{Type: idOrganizationName, Value: "Fake ICP-Brasil"}},
		[]atv{atv{Type: idOrganizationalUnitName, Value: "Apenas para testes - SEM VALOR LEGAL"}},
		[]atv{atv{Type: idCommonName, Value: "Autoridade Certificadora Raiz de Testes - SEM VALOR LEGAL"}},
	}
	return NewCertAndKey(name, name, big.NewInt(1), not_before, not_after)
}

func NewCertAndKey(subject, issuer nameT, serial *big.Int, not_before, not_after time.Time) (p12 P12, cerr CodedError) {
	var pair pair_alg_pub_key

	// Generate key pair
	p12.Key, pair, cerr = new_rsa_key(1024)
	if cerr != nil {
		return
	}

	// Set data
	p12.Cert.base.TBSCertificate.Issuer = issuer
	p12.Cert.base.TBSCertificate.Subject = subject
	p12.Cert.base.TBSCertificate.Issuer = issuer
	p12.Cert.base.TBSCertificate.SerialNumber = serial
	p12.Cert.base.TBSCertificate.Validity.NotBeforeTime = not_before
	p12.Cert.base.TBSCertificate.Validity.NotAfterTime = not_after
	p12.Cert.base.TBSCertificate.Signature.Algorithm = idSha512WithRSAEncryption
	p12.Cert.base.SignatureAlgorithm.Algorithm = idSha512WithRSAEncryption
	p12.Cert.base.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm = idSha512WithRSAEncryption
	p12.Cert.base.TBSCertificate.SubjectPublicKeyInfo.PublicKey = pair.PublicKey
	p12.Cert.base.TBSCertificate.SetAppropriateVersion()
	p12.Cert.finish_parsing()

	// Marshal certificate
	cerr = p12.Cert.base.MarshalCert()
	if cerr != nil {
		return
	}

	// Sign certificate
	cerr = Sign(&p12.Cert.base, p12.Key)
	return
}

func (p12 P12) SaveCertToFile(path string) CodedError {
	// Marshal pack
	cerr := p12.Cert.base.MarshalPack()
	if cerr != nil {
		return cerr
	}

	err := ioutil.WriteFile(path, p12.Cert.base.RawContent, 0644)
	if err != nil {
		return NewMultiError("failed to write to file", ERR_FAILED_TO_WRITE_FILE, nil, err)
	}

	return nil
}
