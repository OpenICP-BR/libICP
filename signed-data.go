package icp

import "encoding/asn1"

// Returns the an ObjectIdentifier for id-signedData { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
func IdSignedData() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
}

type SignedDataT struct {
	RawContent       asn1.RawContent
	Version          int
	DigestAlgorithms []DigestAlgorithmIdentifierT `asn1:set`
	EncapContentInfo EncapsulatedContentInfoT
	Certificates     []CertificateChoiceT   `asn1:"tag:0,optional,set"`
	CRLs             []RevocationInfoChoiceT `asn1:"tag:1,optional"`
	SignerInfos      []SignerInfoT           `asn1:set`
}

// Apply algorithm described on RFC5625 Section 5.1 Page 9. This function MUST be called before marshaling.
func (sd *SignedDataT) SetAppropriateVersion() {
	if sd.has_other_type_cert() || sd.has_other_type_crl() {
		sd.Version = 5
	} else {
		if sd.has_v2_cert(){
			sd.Version = 4
		} else {
			if sd.has_v1_cert() || sd.has_v3_signer_info() || !sd.EncapContentInfo.EContentType.Equal(IdData()) {
				sd.Version = 3
			} else {
				sd.Version = 1
			}
		}
	}
}

func (sd *SignedDataT) has_other_type_crl() bool {
	for _, crl := range sd.CRLs {
		if !IsZeroOfUnderlyingType(crl.Other) {
			return true
		}
	}
	return false
}

func (sd *SignedDataT) has_other_type_cert() bool {
	for _, cert := range sd.Certificates {
		if !IsZeroOfUnderlyingType(cert.Other) {
			return true
		}
	}
	return false
}

func (sd *SignedDataT) has_v1_cert() bool {
	for _, cert := range sd.Certificates {
		if !IsZeroOfUnderlyingType(cert.V1AttrCert) {
			return true
		}
	}
	return false
}

func (sd *SignedDataT) has_v2_cert() bool {
	for _, cert := range sd.Certificates {
		if !IsZeroOfUnderlyingType(cert.V2AttrCert) {
			return true
		}
	}
	return false
}

func (sd *SignedDataT) has_v3_signer_info() bool {
	for _, info := range sd.SignerInfos {
		if info.Version == 3 {
			return true
		}
	}
	return false
}

type IssuerAndSerialNumberT struct {
	RawContent   asn1.RawContent
	Issuer       NameT
	SerialNumber int
}
