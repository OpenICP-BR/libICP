package libICP

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/gjvnq/asn1"
)

type pfx_raw struct {
	RawContent asn1.RawContent
	Version    int
	AuthSafe   content_info
	MacData    mac_data `asn1:"optional,omitempty"`
}

func (pfx *pfx_raw) Marshal(password string, cert certificate_pack, key *rsa.PrivateKey) CodedError {
	// Basics
	pfx.Version = 3
	pfx.AuthSafe.ContentType = idData
	safe := make([]safe_bag_octet, 1)
	pfx.AuthSafe.Content = safe

	// Encode private key
	enc_key_bag := encrypted_private_key_info{}
	cerr := enc_key_bag.SetKey(key, password)
	if cerr != nil {
		return cerr
	}
	safe[0].BagId = idData
	key_safe := make(safe_contents, 1)
	key_safe[0].BagId = idPKCS12_8ShroudedKeyBag
	key_safe[0].BagValue = enc_key_bag
	safe[0].BagValue = key_safe

	// key_safe[0].BagValue =
	// safe[1].BagValue = ?

	// Encode certificate
	// safe[1].BagId = idEncryptedData
	// safe[0].BagValue

	// Final encoding
	dat, err := asn1.Marshal(pfx)
	if err != nil {
		return NewMultiError("failed to marshal pfx_raw", ERR_FAILED_TO_ENCODE, nil, err)
	}
	pfx.RawContent = asn1.RawContent(dat)
	return nil
}

type mac_data struct {
	Mac        object_digest_info
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

// ASN.1 definition:
//     AuthenticatedSafe ::= SEQUENCE OF ContentInfo
//     -- Data if unencrypted
//     -- EncryptedData if password-encrypted
//     -- EnvelopedData if public key-encrypted
type authenticated_safe []content_info

type safe_contents []safe_bag

type safe_bag_octet struct {
	RawContent asn1.RawContent
	BagId      asn1.ObjectIdentifier
	BagValue   interface{} `asn1:"explicit,tag:0,octet"`
	BagAttr    []attribute `asn1:"set,optional,omitempty"`
}

type safe_bag struct {
	RawContent asn1.RawContent
	BagId      asn1.ObjectIdentifier
	BagValue   interface{} `asn1:"explicit,tag:0"`
	BagAttr    []attribute `asn1:"set,optional,omitempty"`
}

// A KeyBag is a PKCS #8 PrivateKeyInfo. Note that a KeyBag contains only one private key. (OID: pkcs-12 10 1 1)
//     KeyBag ::= PrivateKeyInfo
type private_key_info struct {
	RawContent          asn1.RawContent
	Version             int
	PrivateKeyAlgorithm algorithm_identifier
	PrivateKey          []byte
	Attributes          []attribute `asn1:"tag:0,implicit,set"`
}

func (s *private_key_info) SetKey(key *rsa.PrivateKey) CodedError {
	var cerr CodedError

	s.Version = 0
	s.Attributes = nil
	s.PrivateKeyAlgorithm = algorithm_identifier{}
	s.PrivateKeyAlgorithm.Algorithm = idRSAEncryption
	s.PrivateKey, cerr = marshal_rsa_private_key(key)
	if cerr != nil {
		return cerr
	}

	dat, err := asn1.Marshal(s)
	if err != nil {
		return NewMultiError("failed to marshal private_key_info", ERR_FAILED_TO_ENCODE, nil, err)
	}

	s.RawContent = asn1.RawContent(dat)
	return nil
}

type encrypted_private_key_info struct {
	RawContent asn1.RawContent
	Alg        algorithm_identifier
	Data       []byte
}

func (s *encrypted_private_key_info) SetKey(priv *rsa.PrivateKey, password string) CodedError {
	info := private_key_info{}
	cerr := info.SetKey(priv)
	if cerr != nil {
		return cerr
	}
	return s.SetData(info.RawContent, password)
}

// BUG(x): It supports only idPbeWithSHAAnd3KeyTripleDES_CBC with SHA1
func (s *encrypted_private_key_info) SetData(msg []byte, password string) CodedError {
	param := pbes1_parameters{}

	// Generate salt
	param.Salt = make([]byte, 8*3)
	_, err := rand.Read(param.Salt)
	if err != nil {
		return NewMultiError("faield to generate random salt", ERR_SECURE_RANDOM, nil, err)
	}
	param.Iterations = 50000

	// Set basics
	s.Alg.Algorithm = idPbeWithSHAAnd3KeyTripleDES_CBC
	s.Alg.Parameters = make([]interface{}, 2)
	s.Alg.Parameters[0] = param.Salt
	s.Alg.Parameters[1] = param.Iterations

	// Convert password
	byte_password := conv_password(password)

	// Generate key
	k := make([]byte, 0)
	iv := make([]byte, 0)
	for i := 0; i < 3; i++ {
		sub_salt := param.Salt[i*8 : (i+1)*8-1]
		sub_k, sub_iv := gen_subkey(byte_password, sub_salt, param.Iterations)
		k = append(k, sub_k...)
		iv = append(iv, sub_iv...)
		fmt.Println("LEN = ", len(iv))
	}

	// Encrypt
	block, err := des.NewTripleDESCipher(k)
	if err != nil {
		return NewMultiError("faield to open block cipher for triple DES", ERR_FAILED_TO_ENCODE, nil, err)
	}
	block_mode := cipher.NewCBCEncrypter(block, iv[:8])
	paded_msg := pad_msg(msg)
	s.Data = make([]byte, len(paded_msg))
	block_mode.CryptBlocks(s.Data, paded_msg)

	// Encode
	final, err := asn1.Marshal(s)
	if err != nil {
		return NewMultiError("failed to marshal encrypted_private_key_info", ERR_FAILED_TO_ENCODE, nil, err)
	}

	s.RawContent = asn1.RawContent(final)
	return nil
}

func gen_subkey(byte_password, salt []byte, iterations int) ([]byte, []byte) {
	// Derive key
	dk := pbkdf1_sha1(byte_password, salt, iterations, 16)

	// See RFC 2898 Section 6.1.1
	k := dk[:8]
	iv := dk[8:]
	return k, iv
}

func pad_msg(msg []byte) []byte {
	ps := make([]byte, 8-(len(msg)%8))
	for i := 0; i < len(ps); i++ {
		ps[i] = byte(len(ps))
	}
	return append(msg, ps...)
}

func conv_password(password string) []byte {
	runes := []rune(password)
	if runes[len(runes)-1] != 0 {
		runes = append(runes, 0)
	}

	seq := utf16.Encode(runes)
	passwd := make([]byte, 2*len(seq))
	for i, _ := range seq {
		binary.BigEndian.PutUint16(passwd[2*i:], seq[i])
		fmt.Printf("%0x %0x ", passwd[2*i], passwd[2*i+1])
	}
	fmt.Println()

	return passwd
}
