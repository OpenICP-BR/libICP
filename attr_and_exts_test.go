package libICP

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AttributeCertificateInfo_SetAppropriateVersion(t *testing.T) {
	attr_cert_info := attribute_certificate_info{}
	attr_cert_info.SetAppropriateVersion()
	assert.Equal(t, 1, attr_cert_info.Version, "The version MUST always be 1 (see RFC3281 Section 4.1 Page 7)")
}

func Test_ExtKeyUsage_FromExtension_1(t *testing.T) {
	raw_ext := extension{}
	ext := ext_key_usage{}
	err := ext.FromExtension(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}

func Test_ExtKeyUsage_FromExtension_2(t *testing.T) {
	raw_ext := extension{}
	raw_ext.ExtnValue = []byte{3, 2, 1, 6}
	ext := ext_key_usage{}
	err := ext.FromExtension(raw_ext)
	require.Nil(t, err)
	assert.True(t, ext.Exists)
	assert.False(t, ext.DigitalSignature)
	assert.False(t, ext.NonRepudiation)
	assert.False(t, ext.KeyEncipherment)
	assert.False(t, ext.DataEncipherment)
	assert.False(t, ext.KeyAgreement)
	assert.True(t, ext.KeyCertSign)
	assert.True(t, ext.CRLSign)
}

func Test_ExtBasicConstraints_FromExtension_1(t *testing.T) {
	raw_ext := extension{}
	ext := ext_basic_constraints{}
	err := ext.FromExtension(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}

func Test_ExtBasicConstraints_FromExtension_2(t *testing.T) {
	raw_ext := extension{}
	raw_ext.ExtnValue = []byte{0x30, 0x03, 0x01, 0x01, 0xFF}
	ext := ext_basic_constraints{}
	err := ext.FromExtension(raw_ext)
	require.Nil(t, err)
	assert.True(t, ext.Exists)
	assert.True(t, ext.CA)
	assert.Equal(t, 0, ext.PathLen)
}

func Test_ExtCRLDistributionPoints_FromExtension_1(t *testing.T) {
	raw_ext := extension{}
	ext := ext_crl_distribution_points{}
	err := ext.FromExtension(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}

func Test_ExtCRLDistributionPoints_FromExtension_2(t *testing.T) {
	raw_ext := extension{}
	raw_ext.ExtnValue = []byte{0x30, 0x36, 0x30, 0x34, 0xA0, 0x32, 0xA0, 0x30, 0x86, 0x2E, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x61, 0x63, 0x72, 0x61, 0x69, 0x7A, 0x2E, 0x69, 0x63, 0x70, 0x62, 0x72, 0x61, 0x73, 0x69, 0x6C, 0x2E, 0x67, 0x6F, 0x76, 0x2E, 0x62, 0x72, 0x2F, 0x4C, 0x43, 0x52, 0x61, 0x63, 0x72, 0x61, 0x69, 0x7A, 0x76, 0x35, 0x2E, 0x63, 0x72, 0x6C}
	ext := ext_crl_distribution_points{}
	err := ext.FromExtension(raw_ext)
	require.Nil(t, err)
	expected := []string{"http://acraiz.icpbrasil.gov.br/LCRacraizv5.crl"}
	assert.Equal(t, expected, ext.URLs)
}

func Test_ExtAuthorityKeyId_FromExtension_1(t *testing.T) {
	raw_ext := extension{}
	ext := ext_authority_key_id{}
	err := ext.FromExtension(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}

func Test_ExtAuthorityKeyId_FromExtension_2(t *testing.T) {
	raw_ext := extension{}
	raw_ext.ExtnValue = []byte{0x30, 0x16, 0x80, 0x14, 0x69, 0xA8, 0xBE, 0x75, 0xD9, 0xC4, 0xEF, 0x6C, 0xE7, 0x13, 0x45, 0xE4, 0x61, 0x6E, 0xE5, 0x68, 0xF8, 0xB6, 0x40, 0x5E}
	ext := ext_authority_key_id{}
	err := ext.FromExtension(raw_ext)
	require.Nil(t, err)
	expected := []byte{0x69, 0xA8, 0xBE, 0x75, 0xD9, 0xC4, 0xEF, 0x6C, 0xE7, 0x13, 0x45, 0xE4, 0x61, 0x6E, 0xE5, 0x68, 0xF8, 0xB6, 0x40, 0x5E}
	assert.Equal(t, expected, ext.KeyId)
}

func Test_ExtSubjectKeyId_FromExtension_1(t *testing.T) {
	raw_ext := extension{}
	ext := ext_subject_key_id{}
	err := ext.FromExtension(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}

func Test_ExtSubjectKeyId_FromExtension_2(t *testing.T) {
	raw_ext := extension{}
	raw_ext.ExtnValue = []byte{0x04, 0x14, 0x69, 0xA8, 0xBE, 0x75, 0xD9, 0xC4, 0xEF, 0x6C, 0xE7, 0x13, 0x45, 0xE4, 0x61, 0x6E, 0xE5, 0x68, 0xF8, 0xB6, 0x40, 0x5E}
	ext := ext_subject_key_id{}
	err := ext.FromExtension(raw_ext)
	require.Nil(t, err)
	expected := []byte{0x69, 0xA8, 0xBE, 0x75, 0xD9, 0xC4, 0xEF, 0x6C, 0xE7, 0x13, 0x45, 0xE4, 0x61, 0x6E, 0xE5, 0x68, 0xF8, 0xB6, 0x40, 0x5E}
	assert.Equal(t, expected, ext.KeyId)
}
