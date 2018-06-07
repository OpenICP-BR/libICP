package icp

import "encoding/asn1"

type attribute struct {
	RawContent asn1.RawContent
	AttrType   asn1.ObjectIdentifier
	AttrValues []interface{} `asn1:set`
}
