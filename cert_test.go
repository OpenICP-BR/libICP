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

func Test_TBSCertListT_SetAppropriateVersion_1(t *testing.T) {
	lcerts := TBSCertListT{}
	lcerts.SetAppropriateVersion()
	assert.Equal(t, 0, lcerts.Version, "The default version MUST be 0 in order to be omited when enconding (see RFC3280 Section 5.1 Page 49)")
}

func Test_TBSCertListT_SetAppropriateVersion_2(t *testing.T) {
	lcerts := TBSCertListT{}
	lcerts.RevokedCertificates = make([]RevokedCertificateT, 1)
	lcerts.SetAppropriateVersion()
	assert.Equal(t, 0, lcerts.Version, "The default version MUST be 0 in order to be omited when enconding (see RFC3280 Section 5.1 Page 49)")
}

func Test_TBSCertListT_SetAppropriateVersion_3(t *testing.T) {
	lcerts := TBSCertListT{}
	lcerts.CRLExtensions = make([]ExtensionT, 1)
	lcerts.SetAppropriateVersion()
	assert.Equal(t, 1, lcerts.Version, "The version MUST be 1 when crlExtensions is present (see RFC3280 Section 5.1 Page 49)")
}

func Test_TBSCertListT_SetAppropriateVersion_4(t *testing.T) {
	lcerts := TBSCertListT{}
	lcerts.RevokedCertificates = make ([]RevokedCertificateT, 1)
	lcerts.RevokedCertificates[0].CRLEntryExtensions = make([]ExtensionT, 1)
	lcerts.SetAppropriateVersion()
	assert.Equal(t, 1, lcerts.Version, "The version MUST be 1 when revokedCertificates.crlEntryExtensions is present (see RFC3280 Section 5.1 Page 49)")
}