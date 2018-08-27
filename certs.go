package libICP

import (
	"math/big"

	"github.com/OpenICP-BR/asn1"
)

type certificate_choice struct {
	RawContent          asn1.RawContent
	Certificate         Certificate              `asn1:"optional,omitempty"`
	ExtendedCertificate extended_certificate     `asn1:"tag:0,optional,omitempty"`
	V1AttrCert          attribute_certificate_v1 `asn1:"tag:1,optional,omitempty"`
	V2AttrCert          attribute_certificate_v2 `asn1:"tag:2,optional,omitempty"`
	Other               other_certificate_format `asn1:"tag:3,optional,omitempty"`
}

type extended_certificate struct {
	ExtendedCertificateInfo extended_certificate_info
	SignatureAlgorithm      algorithm_identifier
	Signature               asn1.BitString
}

type extended_certificate_info struct {
	Version          int
	Certificate      Certificate
	UnauthAttributes attribute `asn1:"set"`
}

type other_certificate_format struct {
	RawContent      asn1.RawContent
	OtherCertFormat asn1.ObjectIdentifier
	OtherCert       interface{}
}

type revocation_info_choice struct {
	RawContent asn1.RawContent
	CRL        certificate_list             `asn1:"optional,omitempty"`
	Other      other_revocation_info_format `asn1:"tag:1,optional,omitempty"`
}

type other_revocation_info_format struct {
	RawContent         asn1.RawContent
	OtherRevInfoFormat asn1.ObjectIdentifier
	OtherRevInfo       interface{} `asn1:"optional,omitempty"`
}

type certificate_pack struct {
	RawContent         asn1.RawContent
	TBSCertificate     tbs_certificate
	SignatureAlgorithm algorithm_identifier
	Signature          asn1.BitString
}

type tbs_certificate struct {
	RawContent           asn1.RawContent
	Version              int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber         *big.Int
	Signature            algorithm_identifier
	Issuer               nameT
	Validity             generalized_validity
	Subject              nameT
	SubjectPublicKeyInfo pair_alg_pub_key
	IssuerUniqueID       asn1.BitString `asn1:"tag:1,optional,omitempty"`
	SubjectUniqueID      asn1.BitString `asn1:"tag:2,optional,omitempty"`
	Extensions           []extension    `asn1:"tag:3,optional,omitempty,explicit"`
}

func (cert *tbs_certificate) SetAppropriateVersion() {
	cert.Version = 0
	if cert.IssuerUniqueID.BitLength != 0 || cert.SubjectUniqueID.BitLength != 0 {
		cert.Version = 1
	}
	if cert.Extensions != nil && len(cert.Extensions) > 0 {
		cert.Version = 2
	}
}

func (cert certificate_pack) GetRawContent() []byte {
	return cert.TBSCertificate.RawContent
}

func (cert certificate_pack) GetSignatureAlgorithm() algorithm_identifier {
	return cert.SignatureAlgorithm
}

func (cert certificate_pack) GetSignature() []byte {
	return cert.Signature.Bytes
}

func (cert *certificate_pack) SetSignature(dat []byte) {
	cert.Signature.Bytes = dat
}

func (cert *certificate_pack) MarshalCert() CodedError {
	dat, err := asn1.Marshal(cert.TBSCertificate)
	if err != nil {
		return NewMultiError("failed to marshal TBSCertificate", ERR_FAILED_TO_ENCODE, nil, err)
	}

	cert.TBSCertificate.RawContent = asn1.RawContent(dat)
	return nil
}

func (cert *certificate_pack) MarshalPack() CodedError {
	dat, err := asn1.Marshal(cert)
	if err != nil {
		return NewMultiError("failed to marshal certificate pack", ERR_FAILED_TO_ENCODE, nil, err)
	}

	cert.RawContent = asn1.RawContent(dat)
	return nil
}

func (cert certificate_pack) GetBytesToSign() []byte {
	return []byte(cert.TBSCertificate.RawContent)
}

type issuer_and_serial struct {
	RawContent asn1.RawContent
	Issuer     []general_name
	Serial     *big.Int
	IssuerUID  asn1.BitString `asn1:"optional"`
}
