package icp

import (
	"encoding/asn1"
	"time"
)

type certificateT struct {
	RawContent         asn1.RawContent
	TBSCertificate     tbsCertificateT
	SignatureAlgorithm algorithmIdentifierT
	Signature          asn1.BitString
}

type tbsCertificateT struct {
	RawContent           asn1.RawContent
	Version              int `asn:"tag:0,explicit"`
	SerialNumber         int
	Signature            algorithmIdentifierT
	Issuer               nameT
	Validity             generalizedValidityT
	Subject              nameT
	SubjectPublicKeyInfo pairAlgPubKeyT
	IssuerUniqueID       asn1.BitString `asn:"tag:1,optional,omitempty"`
	SubjectUniqueID      asn1.BitString `asn:"tag:2,optional,omitempty"`
	Extensions           []extensionT   `asn:"tag:3,optional,omitempty"`
}

func (cert *tbsCertificateT) SetAppropriateVersion() {
	cert.Version = 0
	if cert.IssuerUniqueID.BitLength != 0 || cert.SubjectUniqueID.BitLength != 0 {
		cert.Version = 1
	}
	if cert.Extensions != nil && len(cert.Extensions) > 0 {
		cert.Version = 2
	}
}

type certificateListT struct {
	RawContent         asn1.RawContent
	TBSCertList        tbsCertListT
	SignatureAlgorithm algorithmIdentifierT
	Signature          asn1.BitString
}

type tbsCertListT struct {
	RawContent          asn1.RawContent
	Version             int `asn1:"optional,omitempty"`
	Signature           algorithmIdentifierT
	Issuer              nameT
	ThisUpdate          time.Time
	NextUpdate          time.Time             `asn1:"optional,omitempty"`
	RevokedCertificates []revokedCertificateT `asn1:"optional,omitempty"`
	CRLExtensions       []extensionT          `asn1:"optional,omitempty,tag:0"`
}

type revokedCertificateT struct {
	RawContent         asn1.RawContent
	UserCertificate    int
	RevocationDate     time.Time
	CRLEntryExtensions []extensionT `asn1:"optional,omitempty"`
}

func (lcerts *tbsCertListT) SetAppropriateVersion() {
	lcerts.Version = 0
	if lcerts.CRLExtensions != nil && len(lcerts.CRLExtensions) > 0 {
		lcerts.Version = 1
	}
	for _, rev := range lcerts.RevokedCertificates {
		if rev.CRLEntryExtensions != nil && len(rev.CRLEntryExtensions) > 0 {
			lcerts.Version = 1
			return
		}
	}
}
