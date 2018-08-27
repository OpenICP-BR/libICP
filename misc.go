package libICP

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"regexp"
	"time"

	"github.com/OpenICP-BR/asn1"
)

const VERSION_MAJOR = 0
const VERSION_MINOR = 0
const VERSION_PATCH = 1

// Returns this library version as a string
func Version() string {
	return fmt.Sprintf("%d.%d.%d", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)
}

// Outputs a byte sequence as pairs of hexadecimal digits separated by colons. Ex: AA:FF:1E
func nice_hex(buf []byte) string {
	ans := ""
	for i := 0; i < len(buf); i++ {
		if i != 0 {
			ans += ":"
		}
		ans += fmt.Sprintf("%X", buf[i:i+1])
	}
	return ans
}

// Outputs a byte sequence as pairs of hexadecimal digitss. Ex: AAFF1E
func to_hex(buf []byte) string {
	ans := ""
	for i := 0; i < len(buf); i++ {
		ans += fmt.Sprintf("%X", buf[i:i+1])
	}
	return ans
}

// Returns nil in case of failure
func from_hex(s string) []byte {
	re := regexp.MustCompile("[^A-Fa-f0-9]")
	s = re.ReplaceAllString(s, "")
	ans, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return ans
}

type content_info struct {
	RawContent  asn1.RawContent
	ContentType asn1.ObjectIdentifier
	Content     interface{} `asn1:"tag:0,explicit,octet"`
}

type content_info_decode_shrouded struct {
	RawContent  asn1.RawContent
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"tag:0,explicit"`
}

type content_info_decode struct {
	RawContent  asn1.RawContent
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit"`
}

type signature_verifiable interface {
	GetRawContent() []byte
	GetSignatureAlgorithm() algorithm_identifier
	GetSignature() []byte
}

type signable interface {
	GetBytesToSign() []byte
	GetSignatureAlgorithm() algorithm_identifier
	SetSignature(sig []byte)
}

func get_hasher(alg_id algorithm_identifier) (hash.Hash, crypto.Hash, CodedError) {
	// Check algorithm
	alg := alg_id.Algorithm
	var hasher hash.Hash
	var hash_alg crypto.Hash
	switch {
	case alg.Equal(idSha1WithRSAEncryption) || alg.Equal(idSha1):
		hasher = sha1.New()
		hash_alg = crypto.SHA1
	case alg.Equal(idSha256WithRSAEncryption) || alg.Equal(idSha256):
		hasher = sha256.New()
		hash_alg = crypto.SHA256
	case alg.Equal(idSha384WithRSAEncryption) || alg.Equal(idSha384):
		hasher = sha512.New384()
		hash_alg = crypto.SHA384
	case alg.Equal(idSha512WithRSAEncryption) || alg.Equal(idSha512):
		hasher = sha512.New()
		hash_alg = crypto.SHA512
	default:
		merr := NewMultiError("unknown algorithm", ERR_UNKOWN_ALGORITHM, nil)
		merr.SetParam("algorithm", alg)
		return nil, crypto.Hash(0), merr
	}
	return hasher, hash_alg, nil
}

func run_hash(hasher hash.Hash, data []byte) []byte {
	hasher.Write(data)
	return hasher.Sum(nil)
}

func get_hasher_and_run(alg_id algorithm_identifier, data []byte) ([]byte, CodedError) {
	hasher, _, cerr := get_hasher(alg_id)
	if cerr != nil {
		return nil, cerr
	}
	hasher.Write(data)
	return hasher.Sum(nil), nil
}

func run_hash_reader(hasher hash.Hash, input io.Reader) ([]byte, CodedError) {
	_, err := io.Copy(hasher, input)
	if err != nil {
		return nil, NewMultiError("failed to hash file", ERR_FAILED_HASH, nil)
	}
	return hasher.Sum(nil), nil
}

func VerifySignaure(object signature_verifiable, pubkey rsa.PublicKey) CodedError {
	// Check algorithm
	hasher, hash_alg, merr := get_hasher(object.GetSignatureAlgorithm())
	if merr != nil {
		return merr
	}

	// Write raw value
	hash_ans := run_hash(hasher, object.GetRawContent())

	// Verify signature
	sig := object.GetSignature()
	err := rsa.VerifyPKCS1v15(&pubkey, hash_alg, hash_ans, sig)
	if err != nil {
		return NewMultiError("failed to verify signature", ERR_BAD_SIGNATURE, nil, err)
	}
	return nil
}

func Sign(object signable, privkey *rsa.PrivateKey) CodedError {
	// Check algorithm
	hasher, hash_alg, merr := get_hasher(object.GetSignatureAlgorithm())
	if merr != nil {
		return merr
	}

	// Hash it
	hash_ans := run_hash(hasher, object.GetBytesToSign())

	// Generate signature
	sig, err := rsa.SignPKCS1v15(rand.Reader, privkey, hash_alg, hash_ans)
	if err != nil {
		return NewMultiError("failed to sign RSA message", ERR_FAILED_TO_SIGN, nil, err)
	}

	object.SetSignature(sig)
	return nil
}

func http_get(url string) ([]byte, int64, CodedError) {
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

const obj_digest_info_public_key = 0
const obj_digest_info_public_key_cert = 1
const obj_digest_info_other_object_types = 2

type object_digest_info struct {
	RawContent         asn1.RawContent
	DigestedObjectType int                   `asn1:"optional,omitempty"`
	OtherObjectTypeID  asn1.ObjectIdentifier `asn1:"optional,omitempty"`
	DigestAlgorithm    algorithm_identifier_decode
	ObjectDigest       asn1.BitString `asn1:"optional,omitempty"`
}

type object_digest_info_simple_decode struct {
	RawContent      asn1.RawContent
	DigestAlgorithm algorithm_identifier_decode
	ObjectDigest    asn1.BitString `asn1:"optional,omitempty"`
}

// Also unmarshals UTCTime
type generalized_validity struct {
	RawContent    asn1.RawContent
	NotBeforeTime time.Time `asn1:"generalized"`
	NotAfterTime  time.Time `asn1:"generalized"`
}

func is_zero_of_underlying_type(x interface{}) bool {
	return reflect.DeepEqual(x, reflect.Zero(reflect.TypeOf(x)).Interface())
}
