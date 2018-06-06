package icp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_AttributeCertificateInfoT_SetAppropriateVersion(t *testing.T) {
	attr_cert_info := AttributeCertificateInfoT{}
	attr_cert_info.SetAppropriateVersion()
	assert.Equal(t, 1, attr_cert_info.Version, "The version MUST always be 1 (see RFC3281 Section 4.1 Page 7)")
}
