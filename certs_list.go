package libICP

import (
	"math/big"
	"time"

	"github.com/OpenICP-BR/asn1"
)

type certificate_list struct {
	RawContent         asn1.RawContent
	TBSCertList        tbs_cert_list
	SignatureAlgorithm algorithm_identifier
	Signature          asn1.BitString
}

func (list *certificate_list) LoadFromDER(data []byte) ([]byte, CodedError) {
	rest, err := asn1.Unmarshal(data, list)
	if err != nil {
		merr := NewMultiError("failed to parse DER CRL", ERR_PARSE_CRL, nil, err)
		merr.SetParam("raw-data", data)
		return rest, merr
	}
	return rest, nil
}

func (list certificate_list) GetRawContent() []byte {
	return list.TBSCertList.RawContent
}

func (list certificate_list) GetSignatureAlgorithm() algorithm_identifier {
	return list.SignatureAlgorithm
}

func (list certificate_list) GetSignature() []byte {
	return list.Signature.Bytes
}

type tbs_cert_list struct {
	RawContent          asn1.RawContent
	Version             int `asn1:"optional,omitempty"`
	Signature           algorithm_identifier
	Issuer              nameT
	ThisUpdate          time.Time
	NextUpdate          time.Time             `asn1:"optional,omitempty"`
	RevokedCertificates []revoked_certificate `asn1:"optional,omitempty"`
	CRLExtensions       []extension           `asn1:"optional,omitempty,tag:0,explicit"`
}

type revoked_certificate struct {
	UserCertificate    *big.Int
	RevocationDate     time.Time
	CRLEntryExtensions []extension `asn1:"optional,omitempty"`
}

func (lcerts *tbs_cert_list) SetAppropriateVersion() {
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

func (lcerts tbs_cert_list) HasCriticalExtension() asn1.ObjectIdentifier {
	for _, ext := range lcerts.CRLExtensions {
		if ext.Critical {
			return ext.ExtnID
		}
	}
	return nil
}

func (lcerts tbs_cert_list) HasCert(serial *big.Int) bool {
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
