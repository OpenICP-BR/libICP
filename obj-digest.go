package icp

import "encoding/asn1"

const objectDigestInfoT_PublicKey = 0
const objectDigestInfoT_PublicKeyCert = 1
const objectDigestInfoT_OtherObjectTypes = 2

type objectDigestInfoT struct {
	RawContent         asn1.RawContent
	DigestedObjectType int
	OtherObjectTypeID  asn1.ObjectIdentifier `asn1:"optional,omitempty"`
	DigestAlgorithm    algorithmIdentifierT
	ObjectDigest       asn1.BitString
}
