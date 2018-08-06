package rawICP

import (
	"crypto/rsa"
	"math/big"
	"time"
)

type P12 struct {
	Cert Certificate
	Key  *rsa.PrivateKey
}

// Generates a new root ca with subject and issuer TESTING_ROOT_CA_SUBJECT
func NewRootCA(not_before, not_after time.Time) (P12, CodedError) {
	name := Name{
		[]ATV{ATV{Type: IdCountryName(), Value: "BR"}},
		[]ATV{ATV{Type: IdOrganizationName(), Value: "Fake ICP-Brasil"}},
		[]ATV{ATV{Type: IdOrganizationalUnitName(), Value: "Apenas para testes - SEM VALOR LEGAL"}},
		[]ATV{ATV{Type: IdCommonName(), Value: "Autoridade Certificadora Raiz de Testes - SEM VALOR LEGAL"}},
	}
	return NewCertAndKey(name, name, big.NewInt(1), not_before, not_after)
}

func NewCertAndKey(subject, issuer Name, serial *big.Int, not_before, not_after time.Time) (p12 P12, cerr CodedError) {
	var pair PairAlgPubKey

	// Generate key pair
	p12.Key, pair, cerr = NewRSAKey(1024)
	if cerr != nil {
		return
	}

	p12.Cert.Base.TBSCertificate.Subject = subject
	p12.Cert.Base.TBSCertificate.Issuer = issuer
	p12.Cert.Base.TBSCertificate.SerialNumber = serial
	p12.Cert.Base.SignatureAlgorithm.Algorithm = IdSha512WithRSAEncryption()
	p12.Cert.Base.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm = IdSha512WithRSAEncryption()
	p12.Cert.Base.TBSCertificate.SubjectPublicKeyInfo.PublicKey = pair.PublicKey
	p12.Cert.Base.TBSCertificate.SetAppropriateVersion()

	cerr = nil
	return
}
