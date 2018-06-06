package icp

import "encoding/asn1"

type AttributeT struct {
	RawContent asn1.RawContent
	Type       asn1.ObjectIdentifier
	Values     []interface{} `asn1:"set"`
}

type ExtensionT struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool
	ExtnValue []byte
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

func AttributeCertificateInfoV1_T_DefaultVersion() int {
	return 0
}

func (attr_cert *AttributeCertificateInfoV1_T) SetDefaultVersion() {
	attr_cert.Version = AttributeCertificateInfoV1_T_DefaultVersion()
}

// Also known as AttributeCertificate
type AttributeCertificateV2_T struct {
	ACInfo             AttributeCertificateInfoT
	SignatureAlgorithm AlgorithmIdentifierT
	SignatureValue     asn1.BitString
}
