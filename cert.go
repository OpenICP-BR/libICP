package icp

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

type certificateT struct {
	TBSCertificate     tbsCertificateT
	SignatureAlgorithm algorithmIdentifierT
	Signature          asn1.BitString
}

type tbsCertificateT struct {
	RawContent           asn1.RawContent
	Version              int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber         *big.Int
	Signature            algorithmIdentifierT
	Issuer               nameT
	Validity             generalizedValidityT
	Subject              nameT
	SubjectPublicKeyInfo pairAlgPubKeyT
	IssuerUniqueID       asn1.BitString `asn1:"tag:1,optional,omitempty"`
	SubjectUniqueID      asn1.BitString `asn1:"tag:2,optional,omitempty"`
	Extensions           []extensionT   `asn1:"tag:3,optional,omitempty,explicit"`
}

func (cert *tbsCertificateT) SetAppropriateVersion() {
	cert.Version = 0
	if cert.IssuerUniqueID.BitLength != 0 || cert.SubjectUniqueID.BitLength != 0 {
		cert.Version = 1
	}
	if cert.Extensions != nil && len(cert.Extensions) > 0 {
		cert.Version = 2
	}
}

func (cert certificateT) raw_content() asn1.RawContent {
	return cert.TBSCertificate.RawContent
}

func (cert certificateT) signature_algorithm() algorithmIdentifierT {
	return cert.SignatureAlgorithm
}

func (cert certificateT) signature() asn1.BitString {
	return cert.Signature
}

func nice_hex(buf []byte) string {
	ans := ""
	for i := 0; i < len(buf); i++ {
		if i != 0 {
			ans += ":"
		}
		ans += fmt.Sprintf("%X", buf[i:i+1])
	}
	return ans
}

type certificateListT struct {
	RawContent         asn1.RawContent
	TBSCertList        tbsCertListT
	SignatureAlgorithm algorithmIdentifierT
	Signature          asn1.BitString
}

func (list *certificateListT) loadFromDER(data []byte) ([]byte, CodedError) {
	rest, err := asn1.Unmarshal(data, list)
	if err != nil {
		merr := NewMultiError("failed to parse DER CRL", ERR_PARSE_CRL, nil, err)
		merr.SetParam("raw-data", data)
		return rest, merr
	}
	return rest, nil
}

func (list certificateListT) raw_content() asn1.RawContent {
	return list.TBSCertList.RawContent
}

func (list certificateListT) signature_algorithm() algorithmIdentifierT {
	return list.SignatureAlgorithm
}

func (list certificateListT) signature() asn1.BitString {
	return list.Signature
}

type tbsCertListT struct {
	RawContent          asn1.RawContent
	Version             int `asn1:"optional,omitempty"`
	Signature           algorithmIdentifierT
	Issuer              nameT
	ThisUpdate          time.Time
	NextUpdate          time.Time             `asn1:"optional,omitempty"`
	RevokedCertificates []revokedCertificateT `asn1:"optional,omitempty"`
	CRLExtensions       []extensionT          `asn1:"optional,omitempty,tag:0,explicit"`
}

type revokedCertificateT struct {
	UserCertificate    *big.Int
	RevocationDate     time.Time
	CRLEntryExtensions []extensionT `asn1:"optional,omitempty"`
}

func (lcerts *tbsCertListT) SetAppropriateVersion() {
	lcerts.Version = 0
	if lcerts.CRLExtensions != nil && len(lcerts.CRLExtensions) > 0 {
		lcerts.Version = 1
	}
	for _, rev := range lcerts.RevokedCertificates {
		if rev.CRLEntryExtensions != nil && len(rev.CRLEntryExtensions) > 0 {
			lcerts.Version = 1
			return
		}
	}
}

func (lcerts tbsCertListT) HasCriticalExtension() asn1.ObjectIdentifier {
	for _, ext := range lcerts.CRLExtensions {
		if ext.Critical {
			return ext.ExtnID
		}
	}
	return nil
}

func (lcerts tbsCertListT) HasCert(serial *big.Int) bool {
	if serial == nil {
		return false
	}
	for _, rev := range lcerts.RevokedCertificates {
		if rev.UserCertificate == nil {
			continue
		}
		if serial.Cmp(rev.UserCertificate) == 0 {
			return true
		}
	}
	return false
}
