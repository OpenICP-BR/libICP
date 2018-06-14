package icp

import (
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
)

type algorithmIdentifierT struct {
	RawContent asn1.RawContent
	Algorithm  asn1.ObjectIdentifier
	Parameters interface{} `asn1:optional,omitempty`
}

type pairAlgPubKeyT struct {
	RawContent asn1.RawContent
	Algorithm  algorithmIdentifierT
	PublicKey  asn1.BitString
}

func (p pairAlgPubKeyT) RSAPubKey() (rsa.PublicKey, error) {
	pub := rsa.PublicKey{}
	_, err := asn1.Unmarshal(p.PublicKey.Bytes, &pub)
	return pub, err
}

type rsaPubKey struct {
	Modulus        *big.Int
	PublicExponent int
}

func idRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
}

func idMd2WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
}

func idMd4WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 3}
}

func idMd5WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
}

func idSha1WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
}

func idSha256WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
}

func idSha384WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
}

func idSha512WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
}
