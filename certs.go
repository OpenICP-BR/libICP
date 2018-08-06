package libICP

import (
	"math/big"

	"github.com/gjvnq/asn1"
)

type CertificateChoice struct {
	RawContent          asn1.RawContent
	Certificate         Certificate            `asn1:"optional,omitempty"`
	ExtendedCertificate ExtendedCertificate    `asn1:"tag:0,optional,omitempty"`
	V1AttrCert          AttributeCertificateV1 `asn1:"tag:1,optional,omitempty"`
	V2AttrCert          AttributeCertificateV2 `asn1:"tag:2,optional,omitempty"`
	Other               OtherCertificateFormat `asn1:"tag:3,optional,omitempty"`
}

type ExtendedCertificate struct {
	ExtendedCertificateInfo ExtendedCertificateInfo
	SignatureAlgorithm      AlgorithmIdentifier
	Signature               asn1.BitString
}

type ExtendedCertificateInfo struct {
	Version          int
	Certificate      Certificate
	UnauthAttributes Attribute `asn1:"set"`
}

type OtherCertificateFormat struct {
	RawContent      asn1.RawContent
	OtherCertFormat asn1.ObjectIdentifier
	OtherCert       interface{}
}

type RevocationInfoChoice struct {
	RawContent asn1.RawContent
	CRL        CertificateList           `asn1:"optional,omitempty"`
	Other      OtherRevocationInfoFormat `asn1:"tag:1,optional,omitempty"`
}

type OtherRevocationInfoFormat struct {
	RawContent         asn1.RawContent
	OtherRevInfoFormat asn1.ObjectIdentifier
	OtherRevInfo       interface{} `asn1:"optional,omitempty"`
}

type CertificatePack struct {
	TBSCertificate     TBSCertificate
	SignatureAlgorithm AlgorithmIdentifier
	Signature          asn1.BitString
}

type TBSCertificate struct {
	RawContent           asn1.RawContent
	Version              int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber         *big.Int
	Signature            AlgorithmIdentifier
	Issuer               Name
	Validity             GeneralizedValidity
	Subject              Name
	SubjectPublicKeyInfo PairAlgPubKey
	IssuerUniqueID       asn1.BitString `asn1:"tag:1,optional,omitempty"`
	SubjectUniqueID      asn1.BitString `asn1:"tag:2,optional,omitempty"`
	Extensions           []Extension    `asn1:"tag:3,optional,omitempty,explicit"`
}

func (cert *TBSCertificate) SetAppropriateVersion() {
	cert.Version = 0
	if cert.IssuerUniqueID.BitLength != 0 || cert.SubjectUniqueID.BitLength != 0 {
		cert.Version = 1
	}
	if cert.Extensions != nil && len(cert.Extensions) > 0 {
		cert.Version = 2
	}
}

func (cert CertificatePack) GetRawContent() []byte {
	return cert.TBSCertificate.RawContent
}

func (cert CertificatePack) GetSignatureAlgorithm() AlgorithmIdentifier {
	return cert.SignatureAlgorithm
}

func (cert CertificatePack) GetSignature() []byte {
	return cert.Signature.Bytes
}

func (cert *CertificatePack) SetSignature(dat []byte) {
	cert.Signature.Bytes = dat
}

func (cert *CertificatePack) Marshal() CodedError {
	dat, err := asn1.Marshal(cert.TBSCertificate)
	if err != nil {
		return NewMultiError("failed to marshal TBSCertificate", ERR_FAILED_TO_ENCODE, nil, err)
	}

	cert.TBSCertificate.RawContent = asn1.RawContent(dat)
	return nil
}

func (cert *CertificatePack) GetBytesToSign() []byte {
	return []byte(cert.TBSCertificate.RawContent)
}

type IssuerAndSerial struct {
	RawContent asn1.RawContent
	Issuer     []GeneralName
	Serial     *big.Int
	IssuerUID  asn1.BitString `asn1:"optional"`
}
