// A golang library for CAdES (CMS Advanced Electronic Signatures) for the Brazilian Public Key Infrastructure (ICP-Brasil).
//
// For more general information see README.md
//
// For unfamiliar terms see: GLOSSARY.md
//
// By G. Queiroz <gabrieljvnq@gmail.com>
//
package icp

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"hash"
)

type signable interface {
	raw_content() asn1.RawContent
	signature_algorithm() algorithmIdentifierT
	signature() asn1.BitString
}

func verify_signaure(object signable, pubkey rsa.PublicKey) CodedError {
	// Check algorithm
	alg := object.signature_algorithm().Algorithm
	var tbs_hasher hash.Hash
	var tbs_hash_alg crypto.Hash
	switch {
	case alg.Equal(idSha1WithRSAEncryption()):
		tbs_hasher = sha1.New()
		tbs_hash_alg = crypto.SHA1
	case alg.Equal(idSha256WithRSAEncryption()):
		tbs_hasher = sha256.New()
		tbs_hash_alg = crypto.SHA256
	case alg.Equal(idSha384WithRSAEncryption()):
		tbs_hasher = sha512.New384()
		tbs_hash_alg = crypto.SHA384
	case alg.Equal(idSha512WithRSAEncryption()):
		tbs_hasher = sha512.New()
		tbs_hash_alg = crypto.SHA512
	default:
		merr := NewMultiError("unknown algorithm", ERR_UNKOWN_ALGORITHM, nil)
		merr.SetParam("algorithm", alg)
		return merr
	}

	// Write raw value
	tbs_hasher.Write(object.raw_content())
	hash_ans := make([]byte, 0)
	hash_ans = tbs_hasher.Sum(hash_ans)

	// Verify signature
	sig := object.signature().Bytes
	err := rsa.VerifyPKCS1v15(&pubkey, tbs_hash_alg, hash_ans, sig)
	if err != nil {
		return NewMultiError("failed to verify signature", ERR_BAD_SIGNATURE, nil, err)
	}
	return nil
}
