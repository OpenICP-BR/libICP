package libICP

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/big"
	"unicode/utf16"

	"github.com/OpenICP-BR/asn1"
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
	pfx.RawContent = nil
	dat, err := asn1.Marshal(pfx)
	if err != nil {
		return NewMultiError("failed to marshal pfx_raw", ERR_FAILED_TO_ENCODE, nil, err)
	}
	pfx.RawContent = asn1.RawContent(dat)
	return nil
}

func (pfx *pfx_raw) Unmarshal(password string) (certificate_pack, *rsa.PrivateKey, CodedError) {
	cert_pack := certificate_pack{}
	got_cert := false
	var ans_key *rsa.PrivateKey

	// Get raw bytes
	new_content := content_info_decode_shrouded{}
	_, err := asn1.Unmarshal(pfx.AuthSafe.RawContent, &new_content)
	if err != nil {
		merr := NewMultiError("failed to parse PFX, get bytes from content_info", ERR_PARSE_PFX, nil, err)
		merr.SetParam("raw-data", pfx.AuthSafe.RawContent)
		return cert_pack, ans_key, merr
	}

	// Decode safe level 1
	safe1 := make([]content_info_decode, 0)
	dat := new_content.Content
	_, err = asn1.Unmarshal(dat, &safe1)
	if err != nil {
		merr := NewMultiError("failed to parse PKCS7 safe bags", ERR_PARSE_PFX, nil, err)
		merr.SetParam("raw-data", to_hex(dat))
		return cert_pack, ans_key, merr
	}

	// For each bag
	for _, bag_l1 := range safe1 {
		// Remove outer octect string if possible
		dat = bag_l1.Content.Bytes
		raw1 := make([]byte, 0)
		_, err = asn1.Unmarshal(dat, &raw1)
		if err == nil {
			dat = raw1
		}

		// Here we should look for keys
		if bag_l1.ContentType.Equal(idData) {
			// Get bags
			safe2 := make([]content_info_decode, 0)
			_, err = asn1.Unmarshal(dat, &safe2)
			if err != nil {
				continue
			}
			// Find the right bag
			for _, bag_l2 := range safe2 {
				if bag_l2.ContentType.Equal(idPKCS12_8ShroudedKeyBag) {
					item := encrypted_private_key_info{}
					item_tmp := encrypted_private_key_info_decode{}

					// First decode key info
					dat = bag_l2.Content.Bytes
					_, err = asn1.Unmarshal(dat, &item_tmp)
					if err != nil {
						continue
					}

					// Decode parameters
					param := pbes1_parameters{}
					dat = item_tmp.Alg.Parameters.FullBytes
					_, err = asn1.Unmarshal(dat, &param)
					if err != nil {
						continue
					}

					// Convert type
					item.EncData = item_tmp.EncData
					item.Alg.Algorithm = item_tmp.Alg.Algorithm
					item.Alg.Parameters = make([]interface{}, 2)
					item.Alg.Parameters[0] = param.Salt
					item.Alg.Parameters[1] = param.Iterations
					item.RawContent = nil

					// Decode data
					cerr := item.GetData(password)
					if cerr != nil {
						continue
					}

					// Decode key info
					key_info := private_key_info{}
					dat = item.DecData
					_, err = asn1.Unmarshal(dat, &key_info)
					if err != nil {
						continue
					}

					// Decode key
					var new_key *rsa.PrivateKey
					new_key, cerr = unmarshal_rsa_private_key(key_info.PrivateKey)
					if cerr != nil {
						continue
					} else {
						ans_key = new_key
					}
				}
			}
		}
		if bag_l1.ContentType.Equal(idEncryptedData) {
			// Decode
			hack := safe_bag_cert_hack_decode{}
			dat = bag_l1.Content.Bytes
			_, err = asn1.Unmarshal(dat, &hack)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}

			fmt.Println("TODO: decode this thing")
			fmt.Println(to_hex(hack.Value.EncValue))
		}
	}

	if ans_key == nil {
		merr := NewMultiError("failed to get private key", ERR_PARSE_PFX, nil, err)
		return cert_pack, ans_key, merr
	}
	if !got_cert {
		merr := NewMultiError("failed to get certificate", ERR_PARSE_PFX, nil, err)
		return cert_pack, ans_key, merr
	}

	return cert_pack, ans_key, nil
}

type mac_data struct {
	Mac        object_digest_info_simple_decode
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

type safe_bag_octet_decode struct {
	RawContent asn1.RawContent
	BagId      asn1.ObjectIdentifier
	BagValue   []byte      `asn1:"explicit,tag:0"`
	BagAttr    []attribute `asn1:"set,optional,omitempty"`
}

type safe_bag struct {
	RawContent asn1.RawContent
	BagId      asn1.ObjectIdentifier
	BagValue   interface{} `asn1:"explicit,tag:0"`
	BagAttr    []attribute `asn1:"set,optional,omitempty"`
}

type safe_bag_decode struct {
	RawContent asn1.RawContent
	BagId      asn1.ObjectIdentifier
	BagValue   asn1.RawValue `asn1:"explicit,tag:0"`
	BagAttr    []attribute   `asn1:"set,optional,omitempty"`
}

type safe_bag_cert_hack_decode struct {
	Version int
	Value   struct {
		Oid   asn1.ObjectIdentifier
		Value struct {
			Alg  asn1.ObjectIdentifier
			Pram struct {
				A []byte
				B int
			}
		}
		EncValue []byte `asn1:"tag:0"`
	}
}

// A KeyBag is a PKCS #8 PrivateKeyInfo. Note that a KeyBag contains only one private key. (OID: pkcs-12 10 1 1)
//     KeyBag ::= PrivateKeyInfo
type private_key_info struct {
	RawContent          asn1.RawContent
	Version             int
	PrivateKeyAlgorithm algorithm_identifier
	PrivateKey          []byte
	Attributes          []attribute `asn1:"tag:0,implicit,set,optional,omitempty"`
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
	EncData    []byte
	DecData    []byte `asn1:"-"`
}

type encrypted_private_key_info_decode struct {
	RawContent asn1.RawContent
	Alg        algorithm_identifier_decode
	EncData    []byte
}

func (s *encrypted_private_key_info) SetKey(priv *rsa.PrivateKey, password string) CodedError {
	info := private_key_info{}
	cerr := info.SetKey(priv)
	if cerr != nil {
		return cerr
	}
	s.DecData = info.RawContent
	return s.SetData(password)
}

func (s *encrypted_private_key_info) SetData(password string) CodedError {
	var cerr CodedError
	param := pbes1_parameters{}

	// Generate salt
	param.Salt = make([]byte, 8)
	_, err := rand.Read(param.Salt)
	if err != nil {
		return NewMultiError("faield to generate random salt", ERR_SECURE_RANDOM, nil, err)
	}

	// This is the same value OpenSSL seems to use
	param.Iterations = 2048

	// Set basics
	s.Alg.Algorithm = idPbeWithSHAAnd3KeyTripleDES_CBC
	s.Alg.Parameters = make([]interface{}, 2)
	s.Alg.Parameters[0] = param.Salt
	s.Alg.Parameters[1] = param.Iterations

	// Convert password
	byte_password := conv_password(password)

	// Encrypt
	s.EncData, cerr = encrypt_PbeWithSHAAnd3KeyTripleDES_CBC(byte_password, param.Iterations, param.Salt, s.DecData)
	if cerr != nil {
		return cerr
	}

	// Encode
	final, err := asn1.Marshal(s)
	if err != nil {
		return NewMultiError("failed to marshal encrypted_private_key_info", ERR_FAILED_TO_ENCODE, nil, err)
	}

	s.RawContent = asn1.RawContent(final)
	return nil
}

func (s *encrypted_private_key_info) GetData(password string) CodedError {
	alg := s.Alg.Algorithm
	byte_password := conv_password(password)
	iterations := 0
	var cerr CodedError
	var salt []byte
	var real_decrypt func(password []byte, iterations int, salt []byte, enc_msg []byte) ([]byte, CodedError)
	ok1 := false
	ok2 := false

	if alg.Equal(idPbeWithSHAAnd3KeyTripleDES_CBC) {
		salt, ok1 = s.Alg.Parameters[0].([]byte)
		iterations, ok2 = s.Alg.Parameters[1].(int)
		real_decrypt = decrypt_PbeWithSHAAnd3KeyTripleDES_CBC

		if !(ok1 && ok2) {
			println("failed")
			println(ok1)
			println(ok2)
			merr := NewMultiError("unsupported parameters", ERR_UNKOWN_ALGORITHM, nil)
			merr.SetParam("alg", s.Alg.Algorithm.String())
			merr.SetParam("alg-param", s.Alg.Parameters)
			return merr
		}
	} else {
		merr := NewMultiError("unsupported encryption algorithm", ERR_UNKOWN_ALGORITHM, nil)
		merr.SetParam("alg", s.Alg.Algorithm.String())
		return merr
	}

	s.DecData, cerr = real_decrypt(byte_password, iterations, salt, s.EncData)
	return cerr
}

// Code taken from github.com/golang/crypto
func sha1Sum(in []byte) []byte {
	sum := sha1.Sum(in)
	return sum[:]
}

// Code taken from github.com/golang/crypto
func fillWithRepeats(pattern []byte, v int) []byte {
	if len(pattern) == 0 {
		return nil
	}
	outputLen := v * ((len(pattern) + v - 1) / v)
	return bytes.Repeat(pattern, (outputLen+len(pattern)-1)/len(pattern))[:outputLen]
}

// Code taken from github.com/golang/crypto
func pbkdf(hash func([]byte) []byte, u, v int, salt, password []byte, r int, ID byte, size int) (key []byte) {
	one := big.NewInt(1)
	// implementation of https://tools.ietf.org/html/rfc7292#appendix-B.2 , RFC text verbatim in comments

	//    Let H be a hash function built around a compression function f:

	//       Z_2^u x Z_2^v -> Z_2^u

	//    (that is, H has a chaining variable and output of length u bits, and
	//    the message input to the compression function of H is v bits).  The
	//    values for u and v are as follows:

	//            HASH FUNCTION     VALUE u        VALUE v
	//              MD2, MD5          128            512
	//                SHA-1           160            512
	//               SHA-224          224            512
	//               SHA-256          256            512
	//               SHA-384          384            1024
	//               SHA-512          512            1024
	//             SHA-512/224        224            1024
	//             SHA-512/256        256            1024

	//    Furthermore, let r be the iteration count.

	//    We assume here that u and v are both multiples of 8, as are the
	//    lengths of the password and salt strings (which we denote by p and s,
	//    respectively) and the number n of pseudorandom bits required.  In
	//    addition, u and v are of course non-zero.

	//    For information on security considerations for MD5 [19], see [25] and
	//    [1], and on those for MD2, see [18].

	//    The following procedure can be used to produce pseudorandom bits for
	//    a particular "purpose" that is identified by a byte called "ID".
	//    This standard specifies 3 different values for the ID byte:

	//    1.  If ID=1, then the pseudorandom bits being produced are to be used
	//        as key material for performing encryption or decryption.

	//    2.  If ID=2, then the pseudorandom bits being produced are to be used
	//        as an IV (Initial Value) for encryption or decryption.

	//    3.  If ID=3, then the pseudorandom bits being produced are to be used
	//        as an integrity key for MACing.

	//    1.  Construct a string, D (the "diversifier"), by concatenating v/8
	//        copies of ID.
	var D []byte
	for i := 0; i < v; i++ {
		D = append(D, ID)
	}

	//    2.  Concatenate copies of the salt together to create a string S of
	//        length v(ceiling(s/v)) bits (the final copy of the salt may be
	//        truncated to create S).  Note that if the salt is the empty
	//        string, then so is S.

	S := fillWithRepeats(salt, v)

	//    3.  Concatenate copies of the password together to create a string P
	//        of length v(ceiling(p/v)) bits (the final copy of the password
	//        may be truncated to create P).  Note that if the password is the
	//        empty string, then so is P.

	P := fillWithRepeats(password, v)

	//    4.  Set I=S||P to be the concatenation of S and P.
	I := append(S, P...)

	//    5.  Set c=ceiling(n/u).
	c := (size + u - 1) / u

	//    6.  For i=1, 2, ..., c, do the following:
	A := make([]byte, c*20)
	var IjBuf []byte
	for i := 0; i < c; i++ {
		//        A.  Set A2=H^r(D||I). (i.e., the r-th hash of D||1,
		//            H(H(H(... H(D||I))))
		Ai := hash(append(D, I...))
		for j := 1; j < r; j++ {
			Ai = hash(Ai)
		}
		copy(A[i*20:], Ai[:])

		if i < c-1 { // skip on last iteration
			// B.  Concatenate copies of Ai to create a string B of length v
			//     bits (the final copy of Ai may be truncated to create B).
			var B []byte
			for len(B) < v {
				B = append(B, Ai[:]...)
			}
			B = B[:v]

			// C.  Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
			//     blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by
			//     setting I_j=(I_j+B+1) mod 2^v for each j.
			{
				Bbi := new(big.Int).SetBytes(B)
				Ij := new(big.Int)

				for j := 0; j < len(I)/v; j++ {
					Ij.SetBytes(I[j*v : (j+1)*v])
					Ij.Add(Ij, Bbi)
					Ij.Add(Ij, one)
					Ijb := Ij.Bytes()
					// We expect Ijb to be exactly v bytes,
					// if it is longer or shorter we must
					// adjust it accordingly.
					if len(Ijb) > v {
						Ijb = Ijb[len(Ijb)-v:]
					}
					if len(Ijb) < v {
						if IjBuf == nil {
							IjBuf = make([]byte, v)
						}
						bytesShort := v - len(Ijb)
						for i := 0; i < bytesShort; i++ {
							IjBuf[i] = 0
						}
						copy(IjBuf[bytesShort:], Ijb)
						Ijb = IjBuf
					}
					copy(I[j*v:(j+1)*v], Ijb)
				}
			}
		}
	}
	//    7.  Concatenate A_1, A_2, ..., A_c together to form a pseudorandom
	//        bit string, A.

	//    8.  Use the first n bits of A as the output of this entire process.
	return A[:size]

	//    If the above process is being used to generate a DES key, the process
	//    should be used to create 64 random bits, and the key's parity bits
	//    should be set after the 64 bits have been produced.  Similar concerns
	//    hold for 2-key and 3-key triple-DES keys, for CDMF keys, and for any
	//    similar keys with parity bits "built into them".
}

func pad_msg(msg []byte) []byte {
	ps := make([]byte, 8-(len(msg)%8))
	for i := 0; i < len(ps); i++ {
		ps[i] = byte(len(ps))
	}
	return append(msg, ps...)
}

func unpad_msg(msg []byte) []byte {
	l := msg[len(msg)-1]
	top := len(msg) - int(l)
	return msg[:top]
}

func conv_password(password string) []byte {
	runes := []rune(password)
	if len(runes) > 0 && runes[len(runes)-1] != 0 {
		runes = append(runes, 0)
	}

	seq := utf16.Encode(runes)
	passwd := make([]byte, 2*len(seq))
	for i, _ := range seq {
		binary.BigEndian.PutUint16(passwd[2*i:], seq[i])
	}

	return passwd
}

func encrypt_PbeWithSHAAnd3KeyTripleDES_CBC(password []byte, iterations int, salt []byte, msg []byte) ([]byte, CodedError) {
	// Generate key
	k := pbkdf(sha1Sum, 20, 64, salt, password, iterations, 1, 24)

	// Generate IV
	iv := pbkdf(sha1Sum, 20, 64, salt, password, iterations, 2, 8)

	// Encrypt
	block, err := des.NewTripleDESCipher(k)
	if err != nil {
		return nil, NewMultiError("faield to open block cipher for triple DES", ERR_FAILED_TO_ENCODE, nil, err)
	}
	block_mode := cipher.NewCBCEncrypter(block, iv)
	paded_msg := pad_msg(msg)
	ans := make([]byte, len(paded_msg))
	block_mode.CryptBlocks(ans, paded_msg)

	return ans, nil
}

func decrypt_PbeWithSHAAnd3KeyTripleDES_CBC(password []byte, iterations int, salt []byte, enc_msg []byte) ([]byte, CodedError) {

	// Derive our key
	k := pbkdf(sha1Sum, 20, 64, salt, password, iterations, 1, 24)

	// Derive the IV
	iv := pbkdf(sha1Sum, 20, 64, salt, password, iterations, 2, 8)

	// Decrypt
	block, err := des.NewTripleDESCipher(k)
	if err != nil {
		return nil, NewMultiError("faield to open block cipher for triple DES", ERR_FAILED_TO_DECODE, nil, err)
	}
	block_mode := cipher.NewCBCDecrypter(block, iv)
	ans := make([]byte, len(enc_msg))
	block_mode.CryptBlocks(ans, enc_msg)
	return unpad_msg(ans), nil
}
