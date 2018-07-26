package icp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IdRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.1", IdRSAEncryption().String())
}

func Test_IdSha1(t *testing.T) {
	assert.Equal(t, "1.3.14.3.2.26", IdSha1().String())
}

func Test_IdSha256(t *testing.T) {
	assert.Equal(t, "2.16.840.1.101.3.4.2.1", IdSha256().String())
}

func Test_IdSha384(t *testing.T) {
	assert.Equal(t, "2.16.840.1.101.3.4.2.2", IdSha384().String())
}

func Test_IdSha512(t *testing.T) {
	assert.Equal(t, "2.16.840.1.101.3.4.2.3", IdSha512().String())
}

func Test_IdSha224(t *testing.T) {
	assert.Equal(t, "2.16.840.1.101.3.4.2.4", IdSha224().String())
}

func Test_IdSha512_224(t *testing.T) {
	assert.Equal(t, "2.16.840.1.101.3.4.2.5", IdSha512_224().String())
}

func Test_IdSha512_256(t *testing.T) {
	assert.Equal(t, "2.16.840.1.101.3.4.2.6", IdSha512_256().String())
}

func Test_IdSha3_224(t *testing.T) {
	assert.Equal(t, "2.16.840.1.101.3.4.2.7", IdSha3_224().String())
}

func Test_IdSha3_256(t *testing.T) {
	assert.Equal(t, "2.16.840.1.101.3.4.2.8", IdSha3_256().String())
}

func Test_IdSha3_384(t *testing.T) {
	assert.Equal(t, "2.16.840.1.101.3.4.2.9", IdSha3_384().String())
}

func Test_IdSha3_512(t *testing.T) {
	assert.Equal(t, "2.16.840.1.101.3.4.2.10", IdSha3_512().String())
}

func Test_IdMd2WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.2", IdMd2WithRSAEncryption().String())
}

func Test_IdMd4WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.3", IdMd4WithRSAEncryption().String())
}

func Test_IdMd5WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.4", IdMd5WithRSAEncryption().String())
}

func Test_IdSha1WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.5", IdSha1WithRSAEncryption().String())
}

func Test_IdSha256WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.11", IdSha256WithRSAEncryption().String())
}

func Test_IdSha384WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.12", IdSha384WithRSAEncryption().String())
}

func Test_IdSha512WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.13", IdSha512WithRSAEncryption().String())
}

func Test_IdSubjectKeyIdentifier(t *testing.T) {
	assert.Equal(t, "2.5.29.14", IdSubjectKeyIdentifier().String())
}

func Test_IdAuthorityKeyIdentifier(t *testing.T) {
	assert.Equal(t, "2.5.29.35", IdAuthorityKeyIdentifier().String())
}

func Test_IdCeBasicConstraints(t *testing.T) {
	assert.Equal(t, "2.5.29.19", IdCeBasicConstraints().String())
}

func Test_IdCeKeyUsage(t *testing.T) {
	assert.Equal(t, "2.5.29.15", IdCeKeyUsage().String())
}

func Test_IdCeCRLDistributionPoint(t *testing.T) {
	assert.Equal(t, "2.5.29.31", IdCeCRLDistributionPoint().String())
}

func Test_IdCtContentInfo(t *testing.T) {
	ans := "1.2.840.113549.1.9.16.1.6"
	assert.Equal(t, ans, IdCtContentInfo().String(), "id-ct-contentInfo MUST be "+ans+" (see RFC5652 Section 3 Page 6)")
}

func Test_IdData(t *testing.T) {
	ans := "1.2.840.113549.1.7.1"
	assert.Equal(t, ans, IdData().String(), "id-data MUST be "+ans+" (see RFC5652 Section 4 Page 6)")
}

func Test_IdSignedData(t *testing.T) {
	ans := "1.2.840.113549.1.7.2"
	assert.Equal(t, ans, IdSignedData().String(), "id-signedData MUST be "+ans+" (see RFC5652 Section 5.1 Page 8)")
}

func Test_OID_Key2String(t *testing.T) {
	assert.Equal(t, "C", OID_Key2String(IdCountryName()))
	assert.Equal(t, "S", OID_Key2String(IdStateOrProvinceName()))
	assert.Equal(t, "L", OID_Key2String(IdLocalityName()))
	assert.Equal(t, "O", OID_Key2String(IdOrganizationName()))
	assert.Equal(t, "OU", OID_Key2String(IdOrganizationalUnitName()))
	assert.Equal(t, "CN", OID_Key2String(IdCommonName()))
	assert.Equal(t, "1.2.840.113549.1.7.1", OID_Key2String(IdData()))
}
