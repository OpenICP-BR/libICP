package icp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_attributeCertificateInfoT_SetAppropriateVersion(t *testing.T) {
	attr_cert_info := attributeCertificateInfoT{}
	attr_cert_info.SetAppropriateVersion()
	assert.Equal(t, 1, attr_cert_info.Version, "The version MUST always be 1 (see RFC3281 Section 4.1 Page 7)")
}
