package icp

import "encoding/asn1"

// Returns the an ObjectIdentifier for id-signedData { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
func idSignedData() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
}

type signedDataT struct {
	RawContent       asn1.RawContent
	Version          int
	DigestAlgorithms []algorithmIdentifierT `asn1:set`
	EncapContentInfo encapsulatedContentInfoT
	Certificates     []certificateChoiceT    `asn1:"tag:0,optional,set"`
	CRLs             []revocationInfoChoiceT `asn1:"tag:1,optional"`
	SignerInfos      []signerInfoT           `asn1:set`
}

// Apply algorithm described on RFC5625 Section 5.1 Page 9. This function MUST be called before marshaling.
func (sd *signedDataT) SetAppropriateVersion() {
	if sd.has_other_type_cert() || sd.has_other_type_crl() {
		sd.Version = 5
	} else {
		if sd.has_v2_cert() {
			sd.Version = 4
		} else {
			if sd.has_v1_cert() || sd.has_v3_signer_info() || !sd.EncapContentInfo.EContentType.Equal(idData()) {
				sd.Version = 3
			} else {
				sd.Version = 1
			}
		}
	}
}

func (sd *signedDataT) has_other_type_crl() bool {
	for _, crl := range sd.CRLs {
		if !isZeroOfUnderlyingType(crl.Other) {
			return true
		}
	}
	return false
}

func (sd *signedDataT) has_other_type_cert() bool {
	for _, cert := range sd.Certificates {
		if !isZeroOfUnderlyingType(cert.Other) {
			return true
		}
	}
	return false
}

func (sd *signedDataT) has_v1_cert() bool {
	for _, cert := range sd.Certificates {
		if !isZeroOfUnderlyingType(cert.V1AttrCert) {
			return true
		}
	}
	return false
}

func (sd *signedDataT) has_v2_cert() bool {
	for _, cert := range sd.Certificates {
		if !isZeroOfUnderlyingType(cert.V2AttrCert) {
			return true
		}
	}
	return false
}

func (sd *signedDataT) has_v3_signer_info() bool {
	for _, info := range sd.SignerInfos {
		if info.Version == 3 {
			return true
		}
	}
	return false
}

type issuerAndSerialNumberT struct {
	RawContent   asn1.RawContent
	Issuer       nameT
	SerialNumber int
}
