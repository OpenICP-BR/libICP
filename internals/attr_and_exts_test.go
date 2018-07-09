package icp_internals

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AttributeCertificateInfo_SetAppropriateVersion(t *testing.T) {
	attr_cert_info := AttributeCertificateInfo{}
	attr_cert_info.SetAppropriateVersion()
	assert.Equal(t, 1, attr_cert_info.Version, "The version MUST always be 1 (see RFC3281 Section 4.1 Page 7)")
}

func Test_ExtKeyUsage_FromExtension_1(t *testing.T) {
	raw_ext := Extension{}
	ext := ExtKeyUsage{}
	err := ext.FromExtension(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}

func Test_ExtKeyUsage_FromExtension_2(t *testing.T) {
	raw_ext := Extension{}
	raw_ext.ExtnValue = []byte{3, 2, 1, 6}
	ext := ExtKeyUsage{}
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
	raw_ext := Extension{}
	ext := ExtBasicConstraints{}
	err := ext.FromExtension(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}

func Test_ExtCRLDistributionPoints_FromExtension_1(t *testing.T) {
	raw_ext := Extension{}
	ext := ExtCRLDistributionPoints{}
	err := ext.FromExtension(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}
