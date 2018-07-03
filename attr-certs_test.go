package icp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_attributeCertificateInfoT_SetAppropriateVersion(t *testing.T) {
	attr_cert_info := attributeCertificateInfoT{}
	attr_cert_info.SetAppropriateVersion()
	assert.Equal(t, 1, attr_cert_info.Version, "The version MUST always be 1 (see RFC3281 Section 4.1 Page 7)")
}

func Test_ExtKeyUsage_fromExtensionT(t *testing.T) {
	raw_ext := extensionT{}
	ext := ExtKeyUsage{}
	err := ext.fromExtensionT(raw_ext)
	require.NotNil(t, err)
	assert.Equal(t, err.Code(), ERR_PARSE_EXTENSION)
}

func Test_ExtBasicConstraints_fromExtensionT(t *testing.T) {
	raw_ext := extensionT{}
	ext := ExtBasicConstraints{}
	err := ext.fromExtensionT(raw_ext)
	require.NotNil(t, err)
	assert.Equal(t, err.Code(), ERR_PARSE_EXTENSION)
}

func Test_ExtCRLDistributionPoints_fromExtensionT(t *testing.T) {
	raw_ext := extensionT{}
	ext := ExtCRLDistributionPoints{}
	err := ext.fromExtensionT(raw_ext)
	require.NotNil(t, err)
	assert.Equal(t, err.Code(), ERR_PARSE_EXTENSION)
}
