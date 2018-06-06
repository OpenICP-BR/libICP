package icp

import "encoding/asn1"

type IssuerSerialT struct {
	RawContent asn1.RawContent
	Issuer     []GeneralNameT
	Serial     int
	IssuerUID  asn1.BitString `asn1:"optional"`
}
