package libICP

import (
	"math/big"

	"github.com/gjvnq/asn1"
)

type attribute struct {
	RawContent asn1.RawContent
	Type       asn1.ObjectIdentifier
	Values     []interface{} `asn1:"set"`
}

type extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool `asn1:"optional"`
	ExtnValue []byte
}

type attribute_certificate_v1 struct {
	AcInfo             attribute_certificate_info_v1
	SignatureAlgorithm algorithm_identifier
	Signature          asn1.BitString
}

type subject_of_attribute_certificate_info_v1 struct {
	BaseCertificateID issuer_and_serial `asn1:"tag:0,optional,omitempty"`
	SubjectName       []general_name    `asn1:"tag:1,optional,omitempty"`
}

type attribute_certificate_info_v1 struct {
	RawContent            asn1.RawContent
	Version               int
	Subject               subject_of_attribute_certificate_info_v1
	Issuer                []general_name
	Signature             algorithm_identifier
	SerialNumber          int
	AttCertValidityPeriod generalized_validity
	Attributes            []attribute
	IssuerUniqueID        asn1.BitString `asn1:"optional"`
	Extensions            []extension    `asn1:"optional"`
}

// Also known as AttributeCertificate
type attribute_certificate_v2 struct {
	RawContent         asn1.RawContent
	ACInfo             attribute_certificate_info
	SignatureAlgorithm algorithm_identifier
	SignatureValue     asn1.BitString
}

type attribute_certificate_info struct {
	RawContent             asn1.RawContent
	Version                int
	Holder                 holder
	IssuerV1               []general_name `asn1:"optional,omitempty"`
	IssuerV2               v2_form        `asn1:"optional,omitempty,tag:0"`
	Signature              algorithm_identifier
	SerialNumber           int
	AttrCertValidityPeriod generalized_validity
	Attributes             []attribute
	IssuerUniqueID         asn1.BitString `asn1:"optional,omitempty"`
	Extensions             []extension    `asn1:"optional,omitempty"`
}

func (acert *attribute_certificate_info) SetAppropriateVersion() {
	acert.Version = 1
}

type v2_form struct {
	RawContent        asn1.RawContent
	IssuerName        []general_name     `asn1:"optional,omitempty"`
	BaseCertificateID issuer_and_serial  `asn1:"optional,omitempty,tag:0"`
	ObjectDigestInfo  object_digest_info `asn1:"optional,omitempty,tag:1"`
}

type ext_key_usage struct {
	Exists           bool
	DigitalSignature bool
	NonRepudiation   bool
	KeyEncipherment  bool
	DataEncipherment bool
	KeyAgreement     bool
	KeyCertSign      bool
	CRLSign          bool
}

func (ans *ext_key_usage) FromExtension(ext extension) CodedError {
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

type ext_basic_constraints struct {
	Exists  bool
	CA      bool
	PathLen int
}

// I had to created this struct because github.com/gjvnq/asn1 does can't ignore fields with `asn1:"-"`
type ext_basic_constraints_raw struct {
	CA      bool
	PathLen int `asn1:"optional"`
}

func (ans *ext_basic_constraints) FromExtension(ext extension) CodedError {
	raw := ext_basic_constraints_raw{}
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

type ext_crl_distribution_points struct {
	Exists bool
	URLs   []string
}

type ext_crl_distribution_points_raw struct {
	DistributionPoint ext_distribution_point `asn1:"optional,tag:0"`
}

type ext_distribution_point struct {
	FullName general_name `asn1:"optional,tag:0"`
}

func (ans *ext_crl_distribution_points) FromExtension(ext extension) CodedError {
	raw := []ext_crl_distribution_points_raw{}
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

type ext_authority_keyid_raw struct {
	KeyId          []byte         `asn1:"tag:0,optional"`
	AuthCertIssuer []general_name `asn1:"tag:1,optional"`
	AuthCertSerial *big.Int       `asn1:"tag:2,optional"`
}

type ext_authority_key_id struct {
	Exists bool
	KeyId  []byte
}

func (ans *ext_authority_key_id) FromExtension(ext extension) CodedError {
	raw := ext_authority_keyid_raw{}
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

type ext_subject_key_id struct {
	Exists bool
	KeyId  []byte
}

func (ans *ext_subject_key_id) FromExtension(ext extension) CodedError {
	_, err := asn1.Unmarshal(ext.ExtnValue, &ans.KeyId)
	if err != nil {
		merr := NewMultiError("failed to parse subject key id extention", ERR_PARSE_EXTENSION, nil, err)
		merr.SetParam("raw-ExtnValue", ext.ExtnValue)
		return merr
	}
	ans.Exists = true
	return nil
}
