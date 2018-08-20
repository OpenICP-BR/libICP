package libICP

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"

	"github.com/gjvnq/asn1"
)

type algorithm_identifier struct {
	RawContent asn1.RawContent
	Algorithm  asn1.ObjectIdentifier
	Parameters []interface{} `asn1:"optional,omitempty"`
}

type algorithm_identifier_decode struct {
	RawContent asn1.RawContent
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional,omitempty"`
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

type pbes1_parameters struct {
	Salt       []byte
	Iterations int
}

// See RFC 3447 Section A.1.2 - RSA private key syntax
type rsa_private_key_raw struct {
	Version         int      // 0 - two primes | 1 - multi prime
	Modulus         *big.Int // n
	PublicExponent  int      // e
	PrivateExponent *big.Int // d
	Prime1          *big.Int // p
	Prime2          *big.Int // q
	Exponent1       *big.Int // d mod (p-1)
	Exponent2       *big.Int // d mod (q-1)
	Coefficient     *big.Int // (inverse of q) mod p

	OtherPrimeInfos []other_prime_info `asn1:"optional,omitempty"`
}

type other_prime_info struct {
	Prime       *big.Int // ri
	Exponent    *big.Int // di
	Coefficient *big.Int // ti
}

func unmarshal_rsa_private_key(dat []byte) (priv rsa.PrivateKey, cerr CodedError) {
	raw := rsa_private_key_raw{}
	_, err := asn1.Unmarshal(dat, &raw)
	if err != nil {
		cerr = NewMultiError("failed to unmarshal RSA private key", ERR_PARSE_RSA_PRIVKEY, nil, err)
		return
	}

	priv.N = raw.Modulus
	priv.E = raw.PublicExponent
	priv.D = raw.PrivateExponent
	priv.Primes = make([]*big.Int, 2+len(raw.OtherPrimeInfos))
	priv.Primes[0] = raw.Prime1
	priv.Primes[1] = raw.Prime2
	for i, item := range raw.OtherPrimeInfos {
		priv.Primes[2+i] = item.Prime
	}
	if len(priv.Primes) == 2 && raw.Version == 0 {
		priv.Precomputed.Dp = raw.Exponent1
		priv.Precomputed.Dq = raw.Exponent2
		priv.Precomputed.Qinv = raw.Coefficient
	} else {
		// It is easier this way ¯\_(ツ)_/¯
		priv.Precompute()
	}
	cerr = nil
	return
}

func marshal_rsa_private_key(priv *rsa.PrivateKey) ([]byte, CodedError) {
	raw := rsa_private_key_raw{}

	// Ensure we have all we need
	priv.Precompute()

	raw.Modulus = priv.N
	raw.PublicExponent = priv.E
	raw.PrivateExponent = priv.D
	raw.OtherPrimeInfos = make([]other_prime_info, len(priv.Primes)-2)
	raw.Prime1 = priv.Primes[0]
	raw.Prime2 = priv.Primes[1]
	raw.Exponent1 = priv.Precomputed.Dp
	raw.Exponent2 = priv.Precomputed.Dq
	raw.Coefficient = priv.Precomputed.Qinv
	for i, prime := range priv.Primes[2:] {
		raw.OtherPrimeInfos[i].Prime = prime
		raw.OtherPrimeInfos[i].Coefficient = priv.Precomputed.CRTValues[i].Coeff
		raw.OtherPrimeInfos[i].Exponent = priv.Precomputed.CRTValues[i].Exp
	}

	out, err := asn1.Marshal(raw)
	if err != nil {
		return nil, NewMultiError("failed to marshal RSA private key", ERR_FAILED_TO_ENCODE, nil, err)
	}

	return out, nil
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
