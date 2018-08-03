package rawICP

import (
	"math/big"
	"time"

	"github.com/gjvnq/asn1"
)

type CertificateList struct {
	RawContent         asn1.RawContent
	TBSCertList        TBSCertList
	SignatureAlgorithm AlgorithmIdentifier
	Signature          asn1.BitString
}

func (list *CertificateList) LoadFromDER(data []byte) ([]byte, CodedError) {
	rest, err := asn1.Unmarshal(data, list)
	if err != nil {
		merr := NewMultiError("failed to parse DER CRL", ERR_PARSE_CRL, nil, err)
		merr.SetParam("raw-data", data)
		return rest, merr
	}
	return rest, nil
}

func (list CertificateList) GetRawContent() []byte {
	return list.TBSCertList.RawContent
}

func (list CertificateList) GetSignatureAlgorithm() AlgorithmIdentifier {
	return list.SignatureAlgorithm
}

func (list CertificateList) GetSignature() []byte {
	return list.Signature.Bytes
}

type TBSCertList struct {
	RawContent          asn1.RawContent
	Version             int `asn1:"optional,omitempty"`
	Signature           AlgorithmIdentifier
	Issuer              Name
	ThisUpdate          time.Time
	NextUpdate          time.Time            `asn1:"optional,omitempty"`
	RevokedCertificates []RevokedCertificate `asn1:"optional,omitempty"`
	CRLExtensions       []Extension          `asn1:"optional,omitempty,tag:0,explicit"`
}

type RevokedCertificate struct {
	UserCertificate    *big.Int
	RevocationDate     time.Time
	CRLEntryExtensions []Extension `asn1:"optional,omitempty"`
}

func (lcerts *TBSCertList) SetAppropriateVersion() {
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

func (lcerts TBSCertList) HasCriticalExtension() asn1.ObjectIdentifier {
	for _, ext := range lcerts.CRLExtensions {
		if ext.Critical {
			return ext.ExtnID
		}
	}
	return nil
}

func (lcerts TBSCertList) HasCert(serial *big.Int) bool {
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
