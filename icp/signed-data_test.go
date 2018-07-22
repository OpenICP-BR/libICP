package icp

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SignedData_SetAppropriateVersion_1(t *testing.T) {
	sd := SignedData{}
	sd.EncapContentInfo.EContentType = IdData()
	sd.SetAppropriateVersion()
	assert.Equal(t, 1, sd.Version, "The version MUST be 1 in this case (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_2(t *testing.T) {
	sd := SignedData{}
	sd.Certificates = make([]CertificateChoice, 1)
	sd.Certificates[0].V1AttrCert.AcInfo.SerialNumber = 9
	sd.SetAppropriateVersion()
	assert.Equal(t, 3, sd.Version, "The version MUST be 3 in this case as: any version 1 attribute certificates are present (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_3(t *testing.T) {
	sd := SignedData{}
	sd.SignerInfos = make([]SignerInfo, 1)
	sd.SignerInfos[0].Version = 3
	sd.SetAppropriateVersion()
	assert.Equal(t, 3, sd.Version, "The version MUST be 3 in this case as: any SignerInfo structures are version 3 (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_4(t *testing.T) {
	sd := SignedData{}
	sd.EncapContentInfo.EContentType = asn1.ObjectIdentifier{}
	sd.SetAppropriateVersion()
	assert.Equal(t, 3, sd.Version, "The version MUST be 3 in this case as: encapContentInfo eContentType is other than id-data (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_5(t *testing.T) {
	sd := SignedData{}
	sd.Certificates = make([]CertificateChoice, 1)
	sd.Certificates[0].V2AttrCert.SignatureValue.BitLength = 1
	sd.SetAppropriateVersion()
	assert.Equal(t, 4, sd.Version, "The version MUST be 4 in this case as: any version 2 attribute certificates are present (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_6(t *testing.T) {
	sd := SignedData{}
	sd.Certificates = make([]CertificateChoice, 1)
	sd.Certificates[0].Other.OtherCert = true
	sd.SetAppropriateVersion()
	assert.Equal(t, 5, sd.Version, "The version MUST be 5 in this case as: any certificates with a type of other are present (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_7(t *testing.T) {
	sd := SignedData{}
	sd.CRLs = make([]RevocationInfoChoice, 1)
	sd.CRLs[0].Other.OtherRevInfo = true
	sd.SetAppropriateVersion()
	assert.Equal(t, 5, sd.Version, "The version MUST be 5 in this case as: any crls with a type of other are present (see RFC5625 Section 5.1 Page 9)")
}
