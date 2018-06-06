package icp

import "encoding/asn1"

type CertificateChoicesT struct {
	RawContent          asn1.RawContent
	Certificate         CertificateT             `asn1:"optional,omitempty"`
	ExtendedCertificate ExtendedCertificateT     `asn1:"tag:0,optional,omitempty"`
	V1AttrCert          AttributeCertificateV1_T `asn1:"tag:1,optional,omitempty"`
	V2AttrCert          AttributeCertificateV2_T `asn1:"tag:2,optional,omitempty"`
	Other               OtherCertificateFormatT  `asn1:"tag:3,optional,omitempty"`
	Interface           interface{}              `asn1:"end_choice"`
}

type ExtendedCertificateT struct {
	ExtendedCertificateInfo ExtendedCertificateInfoT
	SignatureAlgorithm      AlgorithmIdentifierT
	Signature               asn1.BitString
}

type ExtendedCertificateInfoT struct {
	Version          int
	Certificate      CertificateT
	UnauthAttributes AttributeT `asn1:"set"`
}

type OtherCertificateFormatT struct {
	RawContent      asn1.RawContent
	OtherCertFormat asn1.ObjectIdentifier
	OtherCert       interface{}
}
