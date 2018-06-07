package icp

import "encoding/asn1"

// Returns the an ObjectIdentifier for id-signedData { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
func IdSignedData() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
}

type SignedDataT struct {
	RawContent       asn1.RawContent
	Version          CMSVersionT
	DigestAlgorithms []DigestAlgorithmIdentifierT `asn1:set`
	EncapContentInfo EncapsulatedContentInfoT
	Certificates     []CertificateChoiceT   `asn1:"tag:0,optional,set"`
	CRLs             []RevocationInfoChoiceT `asn1:"tag:1,optional"`
	SignerInfos      []SignerInfoT           `asn1:set`
}

// Apply algorithm described on RFC5625 Section 5.1 Page 9. This function MUST be called before marshaling.
func (sd *SignedDataT) SetAppropriateVersion() {
}

type IssuerAndSerialNumberT struct {
	RawContent   asn1.RawContent
	Issuer       NameT
	SerialNumber int
}
