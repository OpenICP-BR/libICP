package icp

import (
	"encoding/asn1"
	"time"
)

type CertificateT struct {
	RawContent         asn1.RawContent
	TBSCertificate     TBSCertificateT
	SignatureAlgorithm AlgorithmIdentifierT
	Signature          asn1.BitString
}

type TBSCertificateT struct {
	RawContent           asn1.RawContent
	Version              int `asn:"tag:0,explicit"`
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

func (cert *TBSCertificateT) SetAppropriateVersion() {
	cert.Version = 0
	if cert.IssuerUniqueID.BitLength != 0 || cert.SubjectUniqueID.BitLength != 0 {
		cert.Version = 1
	}
	if cert.Extensions != nil && len(cert.Extensions) > 0 {
		cert.Version = 2
	}
}

type CertificateListT struct {
	RawContent         asn1.RawContent
	TBSCertList        TBSCertListT
	SignatureAlgorithm AlgorithmIdentifierT
	Signature          asn1.BitString
}

type TBSCertListT struct {
	RawContent          asn1.RawContent
	Version             int `asn1:"optional,omitempty"`
	Signature           AlgorithmIdentifierT
	Issuer              NameT
	ThisUpdate          time.Time
	NextUpdate          time.Time             `asn1:"optional,omitempty"`
	RevokedCertificates []RevokedCertificateT `asn1:"optional,omitempty"`
	CRLExtensions       []ExtensionT          `asn1:"optional,omitempty,tag:0"`
}

type RevokedCertificateT struct {
	RawContent         asn1.RawContent
	UserCertificate    int
	RevocationDate     time.Time
	CRLEntryExtensions []ExtensionT `asn1:"optional,omitempty"`
}

func (lcerts *TBSCertListT) SetAppropriateVersion() {
	if lcerts.Version != 0 {
		lcerts.Version = 2
	}
	if lcerts.CRLExtensions != nil && len(lcerts.CRLExtensions) > 0 {
		lcerts.Version = 2
	}
	for _, rev := range lcerts.RevokedCertificates {
		if rev.CRLEntryExtensions != nil && len(rev.CRLEntryExtensions) > 0 {
			lcerts.Version = 2
			return
		}
	}
}
