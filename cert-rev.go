package icp

import "encoding/asn1"

type revocationInfoChoiceT struct {
	RawContent asn1.RawContent
	CRL        certificateListT           `asn1:"optional,omitempty"`
	Other      otherRevocationInfoFormatT `asn1:"tag:1,optional,omitempty"`
}

type otherRevocationInfoFormatT struct {
	RawContent         asn1.RawContent
	OtherRevInfoFormat asn1.ObjectIdentifier
	OtherRevInfo       interface{} `asn1:"optional,omitempty"`
}
