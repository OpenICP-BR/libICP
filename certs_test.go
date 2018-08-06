package libICP

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_TBSCertificate_SetAppropriateVersion_1(t *testing.T) {
	cert := tbs_certificate{}
	cert.SetAppropriateVersion()
	assert.Equal(t, 0, cert.Version, "The default version MUST be 0 (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificate_SetAppropriateVersion_2(t *testing.T) {
	cert := tbs_certificate{}
	cert.IssuerUniqueID.BitLength = 1
	cert.SetAppropriateVersion()
	assert.Equal(t, 1, cert.Version, "Version MUST be 1 when issuerUniqueID is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificate_SetAppropriateVersion_3(t *testing.T) {
	cert := tbs_certificate{}
	cert.SubjectUniqueID.BitLength = 1
	cert.SetAppropriateVersion()
	assert.Equal(t, 1, cert.Version, "Version MUST be 1 when subjectUniqueID is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificate_SetAppropriateVersion_4(t *testing.T) {
	cert := tbs_certificate{}
	cert.Extensions = make([]extension, 1)
	cert.SetAppropriateVersion()
	assert.Equal(t, 2, cert.Version, "Version MUST be 2 when extensions is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificate_SetAppropriateVersion_5(t *testing.T) {
	cert := tbs_certificate{}
	cert.SubjectUniqueID.BitLength = 1
	cert.Extensions = make([]extension, 1)
	cert.SetAppropriateVersion()
	assert.Equal(t, 2, cert.Version, "Version MUST be 2 when extensions is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificate_SetAppropriateVersion_6(t *testing.T) {
	cert := tbs_certificate{}
	cert.IssuerUniqueID.BitLength = 1
	cert.Extensions = make([]extension, 1)
	cert.SetAppropriateVersion()
	assert.Equal(t, 2, cert.Version, "Version MUST be 2 when extensions is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertificate_SetAppropriateVersion_7(t *testing.T) {
	cert := tbs_certificate{}
	cert.SubjectUniqueID.BitLength = 1
	cert.IssuerUniqueID.BitLength = 1
	cert.Extensions = make([]extension, 1)
	cert.SetAppropriateVersion()
	assert.Equal(t, 2, cert.Version, "Version MUST be 2 when extensions is present (see RFC3280 Section 4.1 Page 14)")
}

func Test_TBSCertList_SetAppropriateVersion_1(t *testing.T) {
	lcerts := tbs_cert_list{}
	lcerts.SetAppropriateVersion()
	assert.Equal(t, 0, lcerts.Version, "The default version MUST be 0 in order to be omited when enconding (see RFC3280 Section 5.1 Page 49)")
}

func Test_TBSCertList_SetAppropriateVersion_2(t *testing.T) {
	lcerts := tbs_cert_list{}
	lcerts.RevokedCertificates = make([]revoked_certificate, 1)
	lcerts.SetAppropriateVersion()
	assert.Equal(t, 0, lcerts.Version, "The default version MUST be 0 in order to be omited when enconding (see RFC3280 Section 5.1 Page 49)")
}

func Test_TBSCertList_SetAppropriateVersion_3(t *testing.T) {
	lcerts := tbs_cert_list{}
	lcerts.CRLExtensions = make([]extension, 1)
	lcerts.SetAppropriateVersion()
	assert.Equal(t, 1, lcerts.Version, "The version MUST be 1 when crlExtensions is present (see RFC3280 Section 5.1 Page 49)")
}

func Test_TBSCertList_SetAppropriateVersion_4(t *testing.T) {
	lcerts := tbs_cert_list{}
	lcerts.RevokedCertificates = make([]revoked_certificate, 1)
	lcerts.RevokedCertificates[0].CRLEntryExtensions = make([]extension, 1)
	lcerts.SetAppropriateVersion()
	assert.Equal(t, 1, lcerts.Version, "The version MUST be 1 when revokedCertificates.crlEntryExtensions is present (see RFC3280 Section 5.1 Page 49)")
}

func Test_Certificate_Signable(t *testing.T) {
	cert := certificate_pack{}
	assert.Equal(t, []byte(cert.TBSCertificate.RawContent), cert.GetRawContent())
	assert.Equal(t, cert.SignatureAlgorithm, cert.GetSignatureAlgorithm())
	assert.Equal(t, cert.Signature.Bytes, cert.GetSignature())
}
