package libICP

import "github.com/gjvnq/asn1"

type pfx_raw struct {
	Version  int
	AuthSafe content_info
	MacData  mac_data `asn1:"optional"`
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

type safe_bag struct {
	RawContents asn1.RawContent
	BagId       asn1.ObjectIdentifier
	BagValue    []byte `asn1:"explicit,tag:0"`
}

// A KeyBag is a PKCS #8 PrivateKeyInfo. Note that a KeyBag contains only one private key. (OID: pkcs-12 10 1 1)
//     KeyBag ::= PrivateKeyInfo
type key_bag private_key_info

type private_key_info struct {
	Version             int
	PrivateKeyAlgorithm algorithm_identifier
	PrivateKey          []byte
	Attributes          []attribute `asn1:"tag:0,implicit,set"`
}
