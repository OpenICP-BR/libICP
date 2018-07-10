package iicp

import (
	"crypto/rsa"
	"encoding/asn1"
)

type AlgorithmIdentifier struct {
	RawContent asn1.RawContent
	Algorithm  asn1.ObjectIdentifier
	Parameters interface{} `asn1:optional,omitempty`
}

type PairAlgPubKey struct {
	RawContent asn1.RawContent
	Algorithm  AlgorithmIdentifier
	PublicKey  asn1.BitString
}

func (p PairAlgPubKey) RSAPubKey() (rsa.PublicKey, error) {
	pub := rsa.PublicKey{}
	_, err := asn1.Unmarshal(p.PublicKey.Bytes, &pub)
	return pub, err
}
