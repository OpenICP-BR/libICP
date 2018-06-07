package icp

import "encoding/asn1"

type attributeT struct {
	RawContent asn1.RawContent
	Type       asn1.ObjectIdentifier
	Values     []interface{} `asn1:"set"`
}

type extensionT struct {
	RawContent asn1.RawContent
	ExtnID     asn1.ObjectIdentifier
	Critical   bool
	ExtnValue  []byte
}

type attributeCertificateV1_T struct {
	RawContent         asn1.RawContent
	AcInfo             attributeCertificateInfoV1_T
	SignatureAlgorithm algorithmIdentifierT
	Signature          asn1.BitString
}

type subjectOfAttributeCertificateInfoV1_T struct {
	RawContent        asn1.RawContent
	BaseCertificateID issuerSerialT  `asn1:"tag:0,optional,omitempty"`
	SubjectName       []generalNameT `asn1:"tag:1,optional,omitempty"`
}

type attributeCertificateInfoV1_T struct {
	RawContent            asn1.RawContent
	Version               int
	Subject               subjectOfAttributeCertificateInfoV1_T
	Issuer                []generalNameT
	Signature             algorithmIdentifierT
	SerialNumber          int
	AttCertValidityPeriod generalizedValidityT
	Attributes            []attributeT
	IssuerUniqueID        asn1.BitString `asn1:"optional"`
	Extensions            []extensionT   `asn1:"optional"`
}

// Also known as AttributeCertificate
type attributeCertificateV2_T struct {
	RawContent         asn1.RawContent
	ACInfo             attributeCertificateInfoT
	SignatureAlgorithm algorithmIdentifierT
	SignatureValue     asn1.BitString
}

type attributeCertificateInfoT struct {
	RawContent             asn1.RawContent
	Version                int
	Holder                 holderT
	IssuerV1               []generalNameT `asn1:"optional,omitempty"`
	IssuerV2               v2FormT        `asn1:"optional,omitempty,tag:0"`
	Signature              algorithmIdentifierT
	SerialNumber           int
	AttrCertValidityPeriod generalizedValidityT
	Attributes             []attributeT
	IssuerUniqueID         asn1.BitString `asn1:"optional,omitempty"`
	Extensions             []extensionT   `asn1:"optional,omitempty"`
}

func (acert *attributeCertificateInfoT) SetAppropriateVersion() {
	acert.Version = 1
}

type v2FormT struct {
	RawContent        asn1.RawContent
	IssuerName        []generalNameT    `asn1:"optional,omitempty"`
	BaseCertificateID issuerSerialT     `asn1:"optional,omitempty,tag:0"`
	ObjectDigestInfo  objectDigestInfoT `asn1:"optional,omitempty,tag:1"`
}
