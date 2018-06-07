package icp

import "encoding/asn1"

type signerInfoT struct {
	RawContent         asn1.RawContent
	Version            int
	Sid_V1             issuerAndSerialNumberT `asn1:"tag:choice"`
	Sid_V3             []byte                 `asn1:"tag:choice"`
	Sid                interface{}            `asn1:"tag:end_choice"`
	DigestAlgorithm    algorithmIdentifierT
	SignedAttrs        []attributeT `asn1:"tag:0,set,optional"`
	SignatureAlgorithm algorithmIdentifierT
	Signature          []byte
	UnsignedAttrs      []attributeT `asn1:"tag:1,set,optional"`
}
