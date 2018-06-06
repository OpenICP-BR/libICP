package icp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_TBSCertificateT_SetAppropriateVersion_1(t *testing.T) {
	cert := TBSCertificateT{}
	cert.SetAppropriateVersion()
	assert.Equal(t, 0, cert.Version, "The default version MUST be 0 (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificateT_SetAppropriateVersion_2(t *testing.T) {
	cert := TBSCertificateT{}
	cert.IssuerUniqueID.BitLength = 1
	cert.SetAppropriateVersion()
	assert.Equal(t, 1, cert.Version, "Version MUST be 1 when issuerUniqueID is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificateT_SetAppropriateVersion_3(t *testing.T) {
	cert := TBSCertificateT{}
	cert.SubjectUniqueID.BitLength = 1
	cert.SetAppropriateVersion()
	assert.Equal(t, 1, cert.Version, "Version MUST be 1 when subjectUniqueID is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificateT_SetAppropriateVersion_4(t *testing.T) {
	cert := TBSCertificateT{}
	cert.Extensions = make([]ExtensionT, 1)
	cert.SetAppropriateVersion()
	assert.Equal(t, 2, cert.Version, "Version MUST be 2 when extensions is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificateT_SetAppropriateVersion_5(t *testing.T) {
	cert := TBSCertificateT{}
	cert.SubjectUniqueID.BitLength = 1
	cert.Extensions = make([]ExtensionT, 1)
	cert.SetAppropriateVersion()
	assert.Equal(t, 2, cert.Version, "Version MUST be 2 when extensions is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificateT_SetAppropriateVersion_6(t *testing.T) {
	cert := TBSCertificateT{}
	cert.IssuerUniqueID.BitLength = 1
	cert.Extensions = make([]ExtensionT, 1)
	cert.SetAppropriateVersion()
	assert.Equal(t, 2, cert.Version, "Version MUST be 2 when extensions is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificateT_SetAppropriateVersion_7(t *testing.T) {
	cert := TBSCertificateT{}
	cert.SubjectUniqueID.BitLength = 1
	cert.IssuerUniqueID.BitLength = 1
	cert.Extensions = make([]ExtensionT, 1)
	cert.SetAppropriateVersion()
	assert.Equal(t, 2, cert.Version, "Version MUST be 2 when extensions is present (see RFC3280 Section 4.1 Page 14)")
}