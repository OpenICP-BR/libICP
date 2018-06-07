package icp

import "encoding/asn1"

type issuerSerialT struct {
	RawContent asn1.RawContent
	Issuer     []generalNameT
	Serial     int
	IssuerUID  asn1.BitString `asn1:"optional"`
}
