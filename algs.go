package libICP

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/gjvnq/asn1"
)

type algorithm_identifier struct {
	RawContent asn1.RawContent
	Algorithm  asn1.ObjectIdentifier
	Parameters []interface{} `asn1:"optional,omitempty"`
}

func (ai algorithm_identifier) ToHex() string {
	return nice_hex(ai.RawContent)
}

type pair_alg_pub_key struct {
	RawContent asn1.RawContent
	Algorithm  algorithm_identifier
	PublicKey  asn1.BitString
}

func (p pair_alg_pub_key) RSAPubKey() (rsa.PublicKey, error) {
	pub := rsa.PublicKey{}
	_, err := asn1.Unmarshal(p.PublicKey.Bytes, &pub)
	return pub, err
}

func new_rsa_key(bits int) (priv *rsa.PrivateKey, pair pair_alg_pub_key, cerr CodedError) {
	var err error

	priv, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		cerr = NewMultiError("failed to generate RSA key", ERR_GEN_KEYS, nil, err)
		return
	}

	pair.PublicKey.Bytes, err = asn1.Marshal(priv.PublicKey)
	pair.PublicKey.BitLength = 8 * len(pair.PublicKey.Bytes)
	if err != nil {
		cerr = NewMultiError("failed to marshal RSA public key", ERR_FAILED_TO_ENCODE, nil, err)
		return
	}

	cerr = nil
	return
}
