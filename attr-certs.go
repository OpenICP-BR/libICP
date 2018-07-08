package icp

import (
	"encoding/asn1"
	"math/big"
)

func idSubjectKeyIdentifier() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 14}
}

func idAuthorityKeyIdentifier() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 35}
}

func idCeBasicConstraints() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 19}
}

func idCeKeyUsage() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 15}
}

func idCeCRLDistributionPoint() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 31}
}

type attributeT struct {
	Type   asn1.ObjectIdentifier
	Values []interface{} `asn1:"set"`
}

type extensionT struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool `asn1:"optional"`
	ExtnValue []byte
}

type attributeCertificateV1_T struct {
	AcInfo             attributeCertificateInfoV1_T
	SignatureAlgorithm algorithmIdentifierT
	Signature          asn1.BitString
}

type subjectOfAttributeCertificateInfoV1_T struct {
	BaseCertificateID issuerSerialT  `asn1:"tag:0,optional,omitempty"`
	SubjectName       []generalNameT `asn1:"tag:1,optional,omitempty"`
}

type attributeCertificateInfoV1_T struct {
	RawContent            asn1.RawContent
	Version               int
	Subject               subjectOfAttributeCertificateInfoV1_T
	Issuer                []generalNameT
	Signature             algorithmIdentifierT
	SerialNumber          int
	AttCertValidityPeriod generalizedValidityT
	Attributes            []attributeT
	IssuerUniqueID        asn1.BitString `asn1:"optional"`
	Extensions            []extensionT   `asn1:"optional"`
}

// Also known as AttributeCertificate
type attributeCertificateV2_T struct {
	RawContent         asn1.RawContent
	ACInfo             attributeCertificateInfoT
	SignatureAlgorithm algorithmIdentifierT
	SignatureValue     asn1.BitString
}

type attributeCertificateInfoT struct {
	RawContent             asn1.RawContent
	Version                int
	Holder                 holderT
	IssuerV1               []generalNameT `asn1:"optional,omitempty"`
	IssuerV2               v2FormT        `asn1:"optional,omitempty,tag:0"`
	Signature              algorithmIdentifierT
	SerialNumber           int
	AttrCertValidityPeriod generalizedValidityT
	Attributes             []attributeT
	IssuerUniqueID         asn1.BitString `asn1:"optional,omitempty"`
	Extensions             []extensionT   `asn1:"optional,omitempty"`
}

func (acert *attributeCertificateInfoT) SetAppropriateVersion() {
	acert.Version = 1
}

type v2FormT struct {
	RawContent        asn1.RawContent
	IssuerName        []generalNameT    `asn1:"optional,omitempty"`
	BaseCertificateID issuerSerialT     `asn1:"optional,omitempty,tag:0"`
	ObjectDigestInfo  objectDigestInfoT `asn1:"optional,omitempty,tag:1"`
}

type ExtKeyUsage struct {
	Exists           bool
	DigitalSignature bool
	NonRepudiation   bool
	KeyEncipherment  bool
	DataEncipherment bool
	KeyAgreement     bool
	KeyCertSign      bool
	CRLSign          bool
}

func (ans *ExtKeyUsage) fromExtensionT(ext extensionT) CodedError {
	seq := asn1.BitString{}
	_, err := asn1.Unmarshal(ext.ExtnValue, &seq)
	if err != nil {
		merr := NewMultiError("failed to parse key usage extention as bit sequence", ERR_PARSE_EXTENSION, nil, err)
		merr.SetParam("raw-ExtnValue", ext.ExtnValue)
		return merr
	}
	ans.Exists = true
	ans.DigitalSignature = (seq.At(0) != 0)
	ans.NonRepudiation = (seq.At(1) != 0)
	ans.KeyEncipherment = (seq.At(2) != 0)
	ans.DataEncipherment = (seq.At(3) != 0)
	ans.KeyAgreement = (seq.At(4) != 0)
	ans.KeyCertSign = (seq.At(5) != 0)
	ans.CRLSign = (seq.At(6) != 0)
	return nil
}

type ExtBasicConstraints struct {
	Exists  bool
	CA      bool
	PathLen int
}

// I had to created this struct because encoding/asn1 does can't ignore fields with `asn1:"-"`
type extBasicConstraintsRawT struct {
	CA      bool
	PathLen int `asn1:"optional"`
}

func (ans *ExtBasicConstraints) fromExtensionT(ext extensionT) CodedError {
	raw := extBasicConstraintsRawT{}
	_, err := asn1.Unmarshal(ext.ExtnValue, &raw)
	if err != nil {
		merr := NewMultiError("failed to parse basic constraints extention", ERR_PARSE_EXTENSION, nil, err)
		merr.SetParam("raw-ExtnValue", ext.ExtnValue)
		return merr
	}
	ans.Exists = true
	ans.CA = raw.CA
	ans.PathLen = raw.PathLen
	return nil
}

type ExtCRLDistributionPoints struct {
	Exists bool
	URLs   []string
}

type extCRLDistributionPointsRawT struct {
	DistributionPoint extDistributionPointT `asn1:"optional,tag:0"`
}

type extDistributionPointT struct {
	FullName generalNameT `asn1:"optional,tag:0"`
}

func (ans *ExtCRLDistributionPoints) fromExtensionT(ext extensionT) CodedError {
	raw := []extCRLDistributionPointsRawT{}
	_, err := asn1.Unmarshal(ext.ExtnValue, &raw)
	if err != nil {
		merr := NewMultiError("failed to parse CRL distribution points extention", ERR_PARSE_EXTENSION, nil, err)
		merr.SetParam("raw-ExtnValue", ext.ExtnValue)
		return merr
	}
	ans.Exists = true
	for _, point := range raw {
		url := point.DistributionPoint.FullName.UniformResourceIdentifier
		if url != "" {
			ans.URLs = append(ans.URLs, url)
		}
	}
	return nil
}

type extAuthorityKeyIdRawT struct {
	KeyId          []byte         `asn1:"tag:0,optional"`
	AuthCertIssuer []generalNameT `asn1:"tag:1,optional"`
	AuthCertSerial *big.Int       `asn1:"tag:2,optional"`
}

type ExtAuthorityKeyId struct {
	Exists bool
	KeyId  []byte
}

func (ans *ExtAuthorityKeyId) fromExtensionT(ext extensionT) CodedError {
	raw := extAuthorityKeyIdRawT{}
	_, err := asn1.Unmarshal(ext.ExtnValue, &raw)
	if err != nil {
		merr := NewMultiError("failed to parse authority key id extention", ERR_PARSE_EXTENSION, nil, err)
		merr.SetParam("raw-ExtnValue", ext.ExtnValue)
		return merr
	}
	ans.Exists = true
	ans.KeyId = raw.KeyId
	return nil
}

type ExtSubjectKeyId struct {
	Exists bool
	KeyId  []byte
}

func (ans *ExtSubjectKeyId) fromExtensionT(ext extensionT) CodedError {
	_, err := asn1.Unmarshal(ext.ExtnValue, &ans.KeyId)
	if err != nil {
		merr := NewMultiError("failed to parse subject key id extention", ERR_PARSE_EXTENSION, nil, err)
		merr.SetParam("raw-ExtnValue", ext.ExtnValue)
		return merr
	}
	ans.Exists = true
	return nil
}
