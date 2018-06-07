package icp

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_idSignedData(t *testing.T) {
	ans := "1.2.840.113549.1.7.2"
	assert.Equal(t, ans, idSignedData().String(), "id-signedData MUST be "+ans+" (see RFC5652 Section 5.1 Page 8)")
}

func Test_signedDataT_SetAppropriateVersion_1(t *testing.T) {
	sd := signedDataT{}
	sd.EncapContentInfo.EContentType = idData()
	sd.SetAppropriateVersion()
	assert.Equal(t, 1, sd.Version, "The version MUST be 1 in this case (see RFC5625 Section 5.1 Page 9)")
}

func Test_signedDataT_SetAppropriateVersion_2(t *testing.T) {
	sd := signedDataT{}
	sd.Certificates = make([]certificateChoiceT, 1)
	sd.Certificates[0].V1AttrCert.AcInfo.SerialNumber = 9
	sd.SetAppropriateVersion()
	assert.Equal(t, 3, sd.Version, "The version MUST be 3 in this case as: any version 1 attribute certificates are present (see RFC5625 Section 5.1 Page 9)")
}

func Test_signedDataT_SetAppropriateVersion_3(t *testing.T) {
	sd := signedDataT{}
	sd.SignerInfos = make([]signerInfoT, 1)
	sd.SignerInfos[0].Version = 3
	sd.SetAppropriateVersion()
	assert.Equal(t, 3, sd.Version, "The version MUST be 3 in this case as: any SignerInfo structures are version 3 (see RFC5625 Section 5.1 Page 9)")
}

func Test_signedDataT_SetAppropriateVersion_4(t *testing.T) {
	sd := signedDataT{}
	sd.EncapContentInfo.EContentType = asn1.ObjectIdentifier{}
	sd.SetAppropriateVersion()
	assert.Equal(t, 3, sd.Version, "The version MUST be 3 in this case as: encapContentInfo eContentType is other than id-data (see RFC5625 Section 5.1 Page 9)")
}

func Test_signedDataT_SetAppropriateVersion_5(t *testing.T) {
	sd := signedDataT{}
	sd.Certificates = make([]certificateChoiceT, 1)
	sd.Certificates[0].V2AttrCert.SignatureValue.BitLength = 1
	sd.SetAppropriateVersion()
	assert.Equal(t, 4, sd.Version, "The version MUST be 4 in this case as: any version 2 attribute certificates are present (see RFC5625 Section 5.1 Page 9)")
}

func Test_signedDataT_SetAppropriateVersion_6(t *testing.T) {
	sd := signedDataT{}
	sd.Certificates = make([]certificateChoiceT, 1)
	sd.Certificates[0].Other.OtherCert = true
	sd.SetAppropriateVersion()
	assert.Equal(t, 5, sd.Version, "The version MUST be 5 in this case as: any certificates with a type of other are present (see RFC5625 Section 5.1 Page 9)")
}

func Test_signedDataT_SetAppropriateVersion_7(t *testing.T) {
	sd := signedDataT{}
	sd.CRLs = make([]revocationInfoChoiceT, 1)
	sd.CRLs[0].Other.OtherRevInfo = true
	sd.SetAppropriateVersion()
	assert.Equal(t, 5, sd.Version, "The version MUST be 5 in this case as: any crls with a type of other are present (see RFC5625 Section 5.1 Page 9)")
}
