package icp

import "encoding/asn1"

type algorithmIdentifierT struct {
	RawContent asn1.RawContent
	Algorithm  asn1.ObjectIdentifier
	Parameters interface{} `asn1:optional,omitempty`
}

type pairAlgPubKeyT struct {
	RawContent asn1.RawContent
	Algorithm  asn1.ObjectIdentifier
	PublicKey  asn1.BitString
}
