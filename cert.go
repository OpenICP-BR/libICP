package icp

import "encoding/asn1"

type CertificateT struct {
	RawContent         asn1.RawContent
	TBSCertificate     TBSCertificateT
	SignatureAlgorithm AlgorithmIdentifierT
	Signature          asn1.BitString
}

type TBSCertificateT struct {
	Version              int `asn:"tag:0"`
	SerialNumber         int
	Signature            AlgorithmIdentifierT
	Issuer               NameT
	Validity             GeneralizedValidityT
	Subject              NameT
	SubjectPublicKeyInfo PairAlgPubKeyT
	IssuerUniqueID       asn1.BitString `asn:"tag:1,optional,omitempty"`
	SubjectUniqueID      asn1.BitString `asn:"tag:2,optional,omitempty"`
	Extensions           []ExtensionT   `asn:"tag:3,optional,omitempty"`
}

func (cert *TBSCertificate) SetAppropriateVersion() {
	if cert.Extensions != nil && len(cert.Extensions) > 0 {
		cert.Version = 3
		return
	}
	if cert.IssuerUniqueID != 0 || cert.SubjectUniqueID != 0 {
		cert.Version = 2
		return
	}
	cert.Version = 1
}
