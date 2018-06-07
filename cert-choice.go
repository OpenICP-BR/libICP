package icp

import "encoding/asn1"

type certificateChoiceT struct {
	RawContent          asn1.RawContent
	Certificate         certificateT             `asn1:"optional,omitempty"`
	ExtendedCertificate extendedCertificateT     `asn1:"tag:0,optional,omitempty"`
	V1AttrCert          attributeCertificateV1_T `asn1:"tag:1,optional,omitempty"`
	V2AttrCert          attributeCertificateV2_T `asn1:"tag:2,optional,omitempty"`
	Other               otherCertificateFormatT  `asn1:"tag:3,optional,omitempty"`
}

type extendedCertificateT struct {
	ExtendedCertificateInfo extendedCertificateInfoT
	SignatureAlgorithm      algorithmIdentifierT
	Signature               asn1.BitString
}

type extendedCertificateInfoT struct {
	Version          int
	Certificate      certificateT
	UnauthAttributes attributeT `asn1:"set"`
}

type otherCertificateFormatT struct {
	RawContent      asn1.RawContent
	OtherCertFormat asn1.ObjectIdentifier
	OtherCert       interface{}
}
