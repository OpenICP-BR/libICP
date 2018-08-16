package libICP

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
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
	param.Salt = make([]byte, 8)
	_, err := rand.Read(param.Salt)
	if err != nil {
		return NewMultiError("faield to generate random salt", ERR_SECURE_RANDOM, nil, err)
	}
	param.Iterations = 2048

	// Set basics
	s.Alg.Algorithm = idPbeWithSHAAnd3KeyTripleDES_CBC
	s.Alg.Parameters = make([]interface{}, 2)
	s.Alg.Parameters[0] = param.Salt
	s.Alg.Parameters[1] = param.Iterations

	// Convert password
	byte_password := conv_password(password)

	// Generate key
	k := make([]byte, 0)
	for i := 0; i < 3; i++ {
		sub_k := rfc7292_b2_gen_sha1(byte_password, param.Salt, 1, 8*8)
		k = append(k, sub_k...)
	}

	// Generate IV
	iv := rfc7292_b2_gen_sha1(byte_password, param.Salt, 2, 8*8)

	// Encrypt
	block, err := des.NewTripleDESCipher(k)
	if err != nil {
		return NewMultiError("faield to open block cipher for triple DES", ERR_FAILED_TO_ENCODE, nil, err)
	}
	block_mode := cipher.NewCBCEncrypter(block, iv)
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

//BUG(r): From math.big: Modular exponentation of inputs of a particular size is not a cryptographically constant-time operation.
func rfc7292_b2_gen_sha1(byte_password, salt []byte, id byte, n int) []byte {
	u := 160
	v := 512
	r := 0 // iteration counter
	p := 8 * len(byte_password)
	s := 8 * len(salt)

	// 1. Construct a string, D (the "diversifier"), by concatenating v/8 copies of ID.
	D := make([]byte, v/8)
	for i := 0; i < len(D); i++ {
		D[i] = id
	}

	// 2. Concatenate copies of the salt together to create a string S of length v(ceiling(s/v)) bits (the final copy of the salt may be truncated to create S). Note that if the salt is the empty string, then so is S.
	S_len := v * int(math.Ceil(float64(s)/float64(v))) / 8
	S := make([]byte, S_len)
	for i := 0; i < S_len; i++ {
		for j := 0; j < len(salt) && i*len(salt)+j < S_len; j++ {
			S[i*len(salt)+j] = salt[j]
		}
	}

	// 3. Concatenate copies of the password together to create a string P of length v(ceiling(p/v)) bits (the final copy of the password may be truncated to create P).  Note that if the password is the empty string, then so is P.
	P_len := v * int(math.Ceil(float64(p)/float64(v))) / 8
	P := make([]byte, P_len)
	for i := 0; i < P_len; i++ {
		for j := 0; j < len(byte_password) && i*len(byte_password)+j < P_len; j++ {
			P[i*len(byte_password)+j] = byte_password[j]
		}
	}

	// 4. Set I=S||P to be the concatenation of S and P.
	I := append(S, P...)

	// 5. Set c=ceiling(n/u).
	c := int(math.Ceil(float64(n) / float64(u)))

	// 6. For i=1, 2, ..., c, do the following:
	A := make([]byte, c)
	for i := 1; i <= c; i++ {
		// A. Set A_i=H^r(D||I). (i.e., the r-th hash of D||1, H(H(H(... H(D||I))))
		Ai := power_sha1(append(D, I...), r)

		// B. Concatenate copies of Ai to create a string B of length v bits (the final copy of Ai may be truncated to create B).
		B := make([]byte, v)
		for i := 0; i < v; i++ {
			for j := 0; j < len(Ai) && i*len(Ai)+j < v; j++ {
				B[i*len(Ai)+j] = Ai[j]
			}
		}
		B_int := big.NewInt(0)
		B_int.SetBytes(B)

		// C. Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by setting I_j=(I_j+B+1) mod 2^v for each j.
		k := int(math.Ceil(float64(s)/float64(v))) + int(math.Ceil(float64(p)/float64(v)))
		block_size := v / 8
		one := big.NewInt(1)
		two := big.NewInt(2)
		v_big := big.NewInt(int64(v))
		for j := 0; j < k; j++ {
			Ij := big.NewInt(0)
			Ij.SetBytes(I[j*block_size : (j+1)*block_size-1])
			Ij.Add(Ij, B_int)
			Ij.Add(Ij, one)
			two2v := big.NewInt(2)
			two2v.Exp(two, v_big, nil)
			Ij.Mod(Ij, two2v)
			ans := Ij.Bytes()
			for cnt := 0; cnt < len(ans); cnt++ {
				I[j*block_size+cnt] = ans[cnt]
			}
		}

		// 7.  Concatenate A_1, A_2, ..., A_c together to form a pseudorandom bit string, A.
		A = append(A, Ai...)
	}

	// 8.  Use the first n bits of A as the output of this entire process.
	return A[:n/8]
}

func power_sha1(base []byte, r int) []byte {
	hasher := sha1.New()
	ans := hasher.Sum(base)
	for i := 1; i < r; i++ {
		ans = hasher.Sum(ans)
	}
	return ans
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
	if len(runes) == 0 || runes[len(runes)-1] != 0 {
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
