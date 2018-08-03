package rawICP

import (
	"crypto/rsa"
	"time"

	"github.com/gjvnq/asn1"
)

type SignedData struct {
	RawContent       asn1.RawContent
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:set`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []CertificateChoice    `asn1:"tag:0,optional,set,omitempty"`
	CRLs             []RevocationInfoChoice `asn1:"tag:1,optional,omitempty"`
	SignerInfos      []SignerInfo           `asn1:set`
}

// Apply algorithm described on RFC5625 Section 5.1 Page 9. This function MUST be called before marshaling.
func (sd *SignedData) SetAppropriateVersion() {
	if sd.HasOtherTypeCert() || sd.HasOtherTypeCRL() {
		sd.Version = 5
	} else {
		if sd.HasV2Cert() {
			sd.Version = 4
		} else {
			if sd.HasV1Cert() || sd.HasV3SignerInfo() || !sd.EncapContentInfo.EContentType.Equal(IdData()) {
				sd.Version = 3
			} else {
				sd.Version = 1
			}
		}
	}
}

func (sd *SignedData) HasOtherTypeCRL() bool {
	for _, crl := range sd.CRLs {
		if !IsZeroOfUnderlyingType(crl.Other) {
			return true
		}
	}
	return false
}

func (sd *SignedData) HasOtherTypeCert() bool {
	for _, cert := range sd.Certificates {
		if !IsZeroOfUnderlyingType(cert.Other) {
			return true
		}
	}
	return false
}

func (sd *SignedData) HasV1Cert() bool {
	for _, cert := range sd.Certificates {
		if !IsZeroOfUnderlyingType(cert.V1AttrCert) {
			return true
		}
	}
	return false
}

func (sd *SignedData) HasV2Cert() bool {
	for _, cert := range sd.Certificates {
		if !IsZeroOfUnderlyingType(cert.V2AttrCert) {
			return true
		}
	}
	return false
}

func (sd *SignedData) HasV3SignerInfo() bool {
	for _, info := range sd.SignerInfos {
		if info.Version == 3 {
			return true
		}
	}
	return false
}

func (sd *SignedData) UpdateAlgs() {
	used := make(map[string]bool)
	algs := make(map[string]AlgorithmIdentifier)

	for _, info := range sd.SignerInfos {
		used[info.DigestAlgorithm.ToHex()] = true
	}
	sd.DigestAlgorithms = make([]AlgorithmIdentifier, len(used))
	i := 0
	for k, _ := range used {
		sd.DigestAlgorithms[i] = algs[k]
		i++
	}
}

type SignerInfo struct {
	RawContent         asn1.RawContent
	Version            int
	Sid_V1             IssuerAndSerial `asn1:"optional,omitempty"`
	Sid_V3             []byte          `asn1:"tag:0,optional,omitempty"`
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"tag:0,set,optional,omitempty"`
	SignedRaw          []byte      `asn1:"-"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      []Attribute `asn1:"tag:1,set,optional,omitempty"`
}

// Apply rule described on RFC5625 Section 5.3 Page 13. This function MUST be called before marshaling.
func (si *SignerInfo) SetAppropriateVersion() {
	si.Version = 0
	if !IsZeroOfUnderlyingType(si.Sid_V1) {
		si.Version = 1
	}
	if !IsZeroOfUnderlyingType(si.Sid_V3) {
		si.Version = 3
	}
}

func (si SignerInfo) GetBytesToSign() []byte {
	// fmt.Println(ToHex(si.SignedRaw))
	return si.SignedRaw[2:]
}

func (si SignerInfo) GetSignatureAlgorithm() AlgorithmIdentifier {
	// This may seem counter intuitive, but the Sign function gets the hasher through this function
	return si.DigestAlgorithm
}

func (si *SignerInfo) SetSignature(sig []byte) {
	si.Signature = sig
}

func (si *SignerInfo) BeforeMarshaling() error {
	si.SetAppropriateVersion()
	return nil
}

func (si *SignerInfo) RemoveSignedAttrByType(attr_type asn1.ObjectIdentifier) {
	for i, attr := range si.SignedAttrs {
		if attr.Type.Equal(attr_type) {
			si.SignedAttrs[i].Values = nil
			si.SignedAttrs = append(si.SignedAttrs[:i], si.SignedAttrs[i+1:]...)
		}
	}
}

func (si *SignerInfo) SetContentTypeAttr(content_type asn1.ObjectIdentifier) {
	// Ensure we will have exactly one content type signed attribute
	si.RemoveSignedAttrByType(IdContentType())
	// Add content type
	attr := Attribute{}
	attr.Type = IdContentType()
	attr.Values = make([]interface{}, 1)
	attr.Values[0] = content_type
	si.SignedAttrs = append(si.SignedAttrs, attr)
}

func (si SignerInfo) DigestEncapContent(encap *EncapsulatedContentInfo) ([]byte, CodedError) {
	return encap.HashAs(si.DigestAlgorithm)
}

func (si *SignerInfo) SetSigningTime(sig_time time.Time) {
	// Ensure we will have exactly one singing time signed attribute
	si.RemoveSignedAttrByType(IdSigningTime())
	// Add singing time
	attr := Attribute{}
	attr.Type = IdSigningTime()
	attr.Values = make([]interface{}, 1)
	attr.Values[0] = sig_time.UTC()
	si.SignedAttrs = append(si.SignedAttrs, attr)
}

func (si *SignerInfo) SetMessageDigestAttr(encap *EncapsulatedContentInfo) CodedError {
	var err CodedError

	// Ensure we will have exactly one message digest signed attribute
	si.RemoveSignedAttrByType(IdMessageDigest())
	// Add message digest
	attr := Attribute{}
	attr.Type = IdMessageDigest()
	attr.Values = make([]interface{}, 1)
	attr.Values[0], err = encap.HashAs(si.DigestAlgorithm)
	if err != nil {
		return err
	}
	si.SignedAttrs = append(si.SignedAttrs, attr)
	return nil
}

func (si *SignerInfo) GetFinalMessageDigest(encap *EncapsulatedContentInfo) ([]byte, CodedError) {
	var err error

	if si.SignedAttrs == nil && encap == nil {
		merr := NewMultiError("signed attributes and encap can't both be nil", ERR_NO_CONTENT, nil)
		merr.SetParam("signer_info", si)
		return nil, merr
	}
	if si.SignedAttrs == nil {
		return encap.HashAs(si.DigestAlgorithm)
	}

	cerr := si.SetMessageDigestAttr(encap)
	if cerr != nil {
		return nil, cerr
	}

	si.SignedRaw, err = asn1.MarshalWithParams(si.SignedAttrs, "set,explicit")
	if err != nil {
		merr := NewMultiError("failed to mashal signed attributes", ERR_FAILED_TO_ENCODE, nil, err)
		merr.SetParam("signer_info", si)
		return nil, merr
	}
	return GetHasherAndRun(si.DigestAlgorithm, si.SignedRaw)
}

func (si *SignerInfo) Sign(privkey *rsa.PrivateKey) CodedError {
	return Sign(si, privkey)
}
