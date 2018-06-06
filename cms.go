package icp

import "encoding/asn1"

// Returns the an ObjectIdentifier for id-ct-contentInfo { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 6 }
func IdCtContentInfo() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 6}
}

// Returns the an ObjectIdentifier for id-data { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }
func IdData() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
}

type CMSVersionT int

type ContentInfoT struct {
	RawContent  asn1.RawContent
	ContentType asn1.ObjectIdentifier
	Content     interface{}
}
