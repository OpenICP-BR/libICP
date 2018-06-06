package icp

import "encoding/asn1"

type AttributeT struct {
	RawContent asn1.RawContent
	Type       asn1.ObjectIdentifier
	Values     []interface{} `asn1:"set"`
}

type ExtensionT struct {
	RawContent asn1.RawContent
	ExtnID     asn1.ObjectIdentifier
	Critical   bool
	ExtnValue  []byte
}

type AttributeCertificateV1_T struct {
	RawContent         asn1.RawContent
	AcInfo             AttributeCertificateInfoV1_T
	SignatureAlgorithm AlgorithmIdentifierT
	Signature          asn1.BitString
}

type SubjectOfAttributeCertificateInfoV1_T struct {
	RawContent        asn1.RawContent
	baseCertificateID IssuerSerialT  `asn1:"tag:0,optional,omitempty"`
	subjectName       []GeneralNameT `asn1:"tag:1,optional,omitempty"`
}

type AttributeCertificateInfoV1_T struct {
	RawContent            asn1.RawContent
	Version               int
	Subject               SubjectOfAttributeCertificateInfoV1_T
	Issuer                []GeneralNameT
	Signature             AlgorithmIdentifierT
	SerialNumber          int
	AttCertValidityPeriod GeneralizedValidityT
	Attributes            []AttributeT
	IssuerUniqueID        asn1.BitString `asn1:"optional"`
	Extensions            []ExtensionT   `asn1:"optional"`
}

// Also known as AttributeCertificate
type AttributeCertificateV2_T struct {
	RawContent         asn1.RawContent
	ACInfo             AttributeCertificateInfoT
	SignatureAlgorithm AlgorithmIdentifierT
	SignatureValue     asn1.BitString
}

type AttributeCertificateInfoT struct {
	RawContent             asn1.RawContent
	Version                int
	Holder                 HolderT
	IssuerV1               []GeneralNameT `asn1:"optional,omitempty"`
	IssuerV2               V2FormT        `asn1:"optional,omitempty,tag:0"`
	Signature              AlgorithmIdentifierT
	SerialNumber           int
	AttrCertValidityPeriod GeneralizedValidityT
	Attributes             []AttributeT
	IssuerUniqueID         asn1.BitString `asn1:"optional,omitempty"`
	Extensions             []ExtensionT   `asn1:"optional,omitempty"`
}

func (acert *AttributeCertificateInfoT) SetAppropriateVersion() {
	acert.Version = 1
}

type V2FormT struct {
	RawContent        asn1.RawContent
	IssuerName        []GeneralNameT    `asn1:"optional,omitempty"`
	BaseCertificateID IssuerSerialT     `asn1:"optional,omitempty,tag:0"`
	ObjectDigestInfo  ObjectDigestInfoT `asn1:"optional,omitempty,tag:1"`
}
