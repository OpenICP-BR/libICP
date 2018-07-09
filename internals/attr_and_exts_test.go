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

func Test_ExtKeyUsage_FromExtensionT(t *testing.T) {
	raw_ext := extensionT{}
	ext := ExtKeyUsage{}
	err := ext.FromExtensionT(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}

func Test_ExtBasicConstraints_FromExtensionT(t *testing.T) {
	raw_ext := extensionT{}
	ext := ExtBasicConstraints{}
	err := ext.FromExtensionT(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}

func Test_ExtCRLDistributionPoints_FromExtensionT(t *testing.T) {
	raw_ext := extensionT{}
	ext := ExtCRLDistributionPoints{}
	err := ext.FromExtensionT(raw_ext)
	require.NotNil(t, err)
	assert.EqualValues(t, ERR_PARSE_EXTENSION, err.Code())
}
