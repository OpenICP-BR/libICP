package icp

import "encoding/asn1"

type RevocationInfoChoiceT struct {
	RawContent asn1.RawContent
	CRL        CertificateListT           `asn1:"optional,omitempty"`
	Other      OtherRevocationInfoFormatT `asn1:"tag:1,optional,omitempty"`
}

type OtherRevocationInfoFormatT struct {
	RawContent         asn1.RawContent
	OtherRevInfoFormat asn1.ObjectIdentifier
	OtherRevInfo       interface{} `asn1:"optional,omitempty"`
}
