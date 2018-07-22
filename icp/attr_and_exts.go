package icp

import (
	"math/big"

	"github.com/gjvnq/asn1"
)

type Attribute struct {
	RawContent asn1.RawContent
	Type       asn1.ObjectIdentifier
	Values     []interface{} `asn1:"set"`
}

type Extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool `asn1:"optional"`
	ExtnValue []byte
}

type AttributeCertificateV1 struct {
	AcInfo             AttributeCertificateInfoV1
	SignatureAlgorithm AlgorithmIdentifier
	Signature          asn1.BitString
}

type SubjectOfAttributeCertificateInfoV1 struct {
	BaseCertificateID IssuerAndSerial `asn1:"tag:0,optional,omitempty"`
	SubjectName       []GeneralName   `asn1:"tag:1,optional,omitempty"`
}

type AttributeCertificateInfoV1 struct {
	RawContent            asn1.RawContent
	Version               int
	Subject               SubjectOfAttributeCertificateInfoV1
	Issuer                []GeneralName
	Signature             AlgorithmIdentifier
	SerialNumber          int
	AttCertValidityPeriod GeneralizedValidity
	Attributes            []Attribute
	IssuerUniqueID        asn1.BitString `asn1:"optional"`
	Extensions            []Extension    `asn1:"optional"`
}

// Also known as AttributeCertificate
type AttributeCertificateV2 struct {
	RawContent         asn1.RawContent
	ACInfo             AttributeCertificateInfo
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type AttributeCertificateInfo struct {
	RawContent             asn1.RawContent
	Version                int
	Holder                 Holder
	IssuerV1               []GeneralName `asn1:"optional,omitempty"`
	IssuerV2               V2Form        `asn1:"optional,omitempty,tag:0"`
	Signature              AlgorithmIdentifier
	SerialNumber           int
	AttrCertValidityPeriod GeneralizedValidity
	Attributes             []Attribute
	IssuerUniqueID         asn1.BitString `asn1:"optional,omitempty"`
	Extensions             []Extension    `asn1:"optional,omitempty"`
}

func (acert *AttributeCertificateInfo) SetAppropriateVersion() {
	acert.Version = 1
}

type V2Form struct {
	RawContent        asn1.RawContent
	IssuerName        []GeneralName    `asn1:"optional,omitempty"`
	BaseCertificateID IssuerAndSerial  `asn1:"optional,omitempty,tag:0"`
	ObjectDigestInfo  ObjectDigestInfo `asn1:"optional,omitempty,tag:1"`
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

func (ans *ExtKeyUsage) FromExtension(ext Extension) CodedError {
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

// I had to created this struct because github.com/gjvnq/asn1 does can't ignore fields with `asn1:"-"`
type ExtBasicConstraintsRaw struct {
	CA      bool
	PathLen int `asn1:"optional"`
}

func (ans *ExtBasicConstraints) FromExtension(ext Extension) CodedError {
	raw := ExtBasicConstraintsRaw{}
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

type ExtCRLDistributionPointsRaw struct {
	DistributionPoint ExtDistributionPoint `asn1:"optional,tag:0"`
}

type ExtDistributionPoint struct {
	FullName GeneralName `asn1:"optional,tag:0"`
}

func (ans *ExtCRLDistributionPoints) FromExtension(ext Extension) CodedError {
	raw := []ExtCRLDistributionPointsRaw{}
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

type ExtAuthorityKeyIdRaw struct {
	KeyId          []byte        `asn1:"tag:0,optional"`
	AuthCertIssuer []GeneralName `asn1:"tag:1,optional"`
	AuthCertSerial *big.Int      `asn1:"tag:2,optional"`
}

type ExtAuthorityKeyId struct {
	Exists bool
	KeyId  []byte
}

func (ans *ExtAuthorityKeyId) FromExtension(ext Extension) CodedError {
	raw := ExtAuthorityKeyIdRaw{}
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

func (ans *ExtSubjectKeyId) FromExtension(ext Extension) CodedError {
	_, err := asn1.Unmarshal(ext.ExtnValue, &ans.KeyId)
	if err != nil {
		merr := NewMultiError("failed to parse subject key id extention", ERR_PARSE_EXTENSION, nil, err)
		merr.SetParam("raw-ExtnValue", ext.ExtnValue)
		return merr
	}
	ans.Exists = true
	return nil
}
