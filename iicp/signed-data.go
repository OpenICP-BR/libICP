package iicp

import "encoding/asn1"

type SignedData struct {
	RawContent       asn1.RawContent
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:set`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []CertificateChoice    `asn1:"tag:0,optional,set"`
	CRLs             []RevocationInfoChoice `asn1:"tag:1,optional"`
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

type SignerInfo struct {
	RawContent         asn1.RawContent
	Version            int
	Sid_V1             IssuerAndSerial `asn1:"tag:choice"`
	Sid_V3             []byte          `asn1:"tag:choice"`
	Sid                interface{}     `asn1:"tag:end_choice"`
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"tag:0,set,optional"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      []Attribute `asn1:"tag:1,set,optional"`
}
