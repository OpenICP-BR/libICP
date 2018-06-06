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

func (cert *TBSCertificateT) SetAppropriateVersion() {
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

type CertificateListT struct {
	TBSCertList        TBSCertListT
	SignatureAlgorithm AlgorithmIdentifierT
	Signature          asn1.BitString
}

// type TBSCertListT  struct  {
//      version                 Version `asn1:"optional,omitempty"`
//      signature               AlgorithmIdentifierT
//      issuer                  NameT
//      thisUpdate              time.Time
//      nextUpdate              time.Time `asn1:"optional,omitempty"`,
//      revokedCertificates     SEQUENCE OF SEQUENCE  {
//           userCertificate         CertificateSerialNumber,
//           revocationDate          Time,
//           crlEntryExtensions      Extensions OPTIONAL
//                                          -- if present, MUST be v2
//                                }  OPTIONAL,
//                                          -- if present, MUST be v2
//      CRLExtensions           []ExtensionT `asn1:"optional,omitempty,tag:0"` }
// }

func (lcerts *TBSCertificateT) SetAppropriateVersion() {
	if lcerts.Version != 0 {
		lcerts.Version = 2
	}
	if cert.CRLExtensions != nil && len(cert.CRLExtensions) > 0 {
		cert.Version = 2
	}
}
