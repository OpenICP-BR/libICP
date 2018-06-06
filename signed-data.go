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
	EncapContentInfo EncapsulatedContentInfoT     `asn1:`
	Certificates     []CertificateChoicesT        `asn1:"tag:0,optional,set"`
	Crls             []RevocationInfoChoiceT      `asn1:"tag:1,optional"`
	SignerInfos      []SignerInfoT                `asn1:set`
}

func (sd *SignerInfosT) SetAppropriateVersion() {
	// algorith in rfc5625 section 5.1 page 10
}
