package icp

import "encoding/asn1"

const ObjectDigestInfoT_PublicKey = 0
const ObjectDigestInfoT_PublicKeyCert = 1
const ObjectDigestInfoT_OtherObjectTypes = 2

type ObjectDigestInfoT struct {
	RawContent         asn1.RawContent
	DigestedObjectType int
	OtherObjectTypeID  asn1.ObjectIdentifier `asn1:"optional,omitempty"`
	DigestAlgorithm    AlgorithmIdentifierT
	ObjectDigest       asn1.BitString
}
