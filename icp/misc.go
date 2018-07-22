package icp

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"
	"io/ioutil"
	"net/http"
	"reflect"
	"time"
)

const VERSION_MAJOR = 0
const VERSION_MINOR = 0
const VERSION_PATCH = 1

// Returns this library version as a string
func Version() string {
	return fmt.Sprintf("%d.%d.%d", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)
}

// Outputs a byte sequence as pairs of hexadecimal digits separated by colons. Ex: AA:FF:1E
func NiceHex(buf []byte) string {
	ans := ""
	for i := 0; i < len(buf); i++ {
		if i != 0 {
			ans += ":"
		}
		ans += fmt.Sprintf("%X", buf[i:i+1])
	}
	return ans
}

type ContentInfo struct {
	RawContent  asn1.RawContent
	ContentType asn1.ObjectIdentifier
	Content     interface{}
}

type EncapsulatedContentInfo struct {
	RawContent   asn1.RawContent
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,omitempty"`
}

/*	According to RFC 5652 Section 5.2 Page 11 Paragraph 2:

	In the degenerate case where there are no signers, the
	EncapsulatedContentInfo value being "signed" is irrelevant.  In this
	case, the content type within the EncapsulatedContentInfo value being
	"signed" MUST be id-data (as defined in Section 4), and the content
	field of the EncapsulatedContentInfo value MUST be omitted.
*/
func (ec *EncapsulatedContentInfo) AdjustForNoSigners() {
	ec.EContentType = IdData()
	ec.EContent = nil
}

type Signable interface {
	GetRawContent() asn1.RawContent
	GetSignatureAlgorithm() AlgorithmIdentifier
	GetSignature() asn1.BitString
}

func VerifySignaure(object Signable, pubkey rsa.PublicKey) CodedError {
	// Check algorithm
	alg := object.GetSignatureAlgorithm().Algorithm
	var tbs_hasher hash.Hash
	var tbs_hash_alg crypto.Hash
	switch {
	case alg.Equal(IdSha1WithRSAEncryption()):
		tbs_hasher = sha1.New()
		tbs_hash_alg = crypto.SHA1
	case alg.Equal(IdSha256WithRSAEncryption()):
		tbs_hasher = sha256.New()
		tbs_hash_alg = crypto.SHA256
	case alg.Equal(IdSha384WithRSAEncryption()):
		tbs_hasher = sha512.New384()
		tbs_hash_alg = crypto.SHA384
	case alg.Equal(IdSha512WithRSAEncryption()):
		tbs_hasher = sha512.New()
		tbs_hash_alg = crypto.SHA512
	default:
		merr := NewMultiError("unknown algorithm", ERR_UNKOWN_ALGORITHM, nil)
		merr.SetParam("algorithm", alg)
		return merr
	}

	// Write raw value
	tbs_hasher.Write(object.GetRawContent())
	hash_ans := make([]byte, 0)
	hash_ans = tbs_hasher.Sum(hash_ans)

	// Verify signature
	sig := object.GetSignature().Bytes
	err := rsa.VerifyPKCS1v15(&pubkey, tbs_hash_alg, hash_ans, sig)
	if err != nil {
		return NewMultiError("failed to verify signature", ERR_BAD_SIGNATURE, nil, err)
	}
	return nil
}

func HTTPGet(url string) ([]byte, int64, CodedError) {
	// Get the data
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		merr := NewMultiError("failed to use GET method", ERR_HTTP, nil, err)
		merr.SetParam("URL", url)
		return nil, 0, merr
	}
	raw, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		merr := NewMultiError("failed to read http response", ERR_HTTP, nil, err)
		merr.SetParam("URL", url)
		return nil, 0, merr
	}

	return raw, resp.ContentLength, nil
}

const ObjectDigestInfo_PublicKey = 0
const ObjectDigestInfo_PublicKeyCert = 1
const ObjectDigestInfo_OtherObjectTypes = 2

type ObjectDigestInfo struct {
	RawContent         asn1.RawContent
	DigestedObjectType int
	OtherObjectTypeID  asn1.ObjectIdentifier `asn1:"optional,omitempty"`
	DigestAlgorithm    AlgorithmIdentifier
	ObjectDigest       asn1.BitString
}

// Also unmarshals UTCTime
type GeneralizedValidity struct {
	RawContent    asn1.RawContent
	NotBeforeTime time.Time `asn1:"generalized"`
	NotAfterTime  time.Time `asn1:"generalized"`
}

func IsZeroOfUnderlyingType(x interface{}) bool {
	return reflect.DeepEqual(x, reflect.Zero(reflect.TypeOf(x)).Interface())
}
