package icp

import "encoding/asn1"

type DigestAlgorithmIdentifierT AlgorithmIdentifierT

type AlgorithmIdentifierT struct {
	RawContent asn1.RawContent
	Algorithm  asn1.ObjectIdentifier
	Parameters interface{} `asn1:optional,omitempty`
}

type PairAlgPubKeyT struct {
	RawContent asn1.RawContent
	Algorithm  asn1.ObjectIdentifier
	PublicKey  asn1.BitString
}
