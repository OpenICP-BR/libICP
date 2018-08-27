package libICP

import (
	"crypto/rsa"
	"math/big"
	"testing"
	"time"

	"github.com/OpenICP-BR/asn1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SignedData_SetAppropriateVersion_1(t *testing.T) {
	sd := signed_data_raw{}
	sd.EncapContentInfo.EContentType = idData
	sd.set_appropriate_version()
	assert.Equal(t, 1, sd.Version, "The version MUST be 1 in this case (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_2(t *testing.T) {
	sd := signed_data_raw{}
	sd.Certificates = make([]certificate_choice, 1)
	sd.Certificates[0].V1AttrCert.AcInfo.SerialNumber = 9
	sd.set_appropriate_version()
	assert.Equal(t, 3, sd.Version, "The version MUST be 3 in this case as: any version 1 attribute certificates are present (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_3(t *testing.T) {
	sd := signed_data_raw{}
	sd.SignerInfos = make([]signer_info_raw, 1)
	sd.SignerInfos[0].Version = 3
	sd.set_appropriate_version()
	assert.Equal(t, 3, sd.Version, "The version MUST be 3 in this case as: any SignerInfo structures are version 3 (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_4(t *testing.T) {
	sd := signed_data_raw{}
	sd.EncapContentInfo.EContentType = asn1.ObjectIdentifier{}
	sd.set_appropriate_version()
	assert.Equal(t, 3, sd.Version, "The version MUST be 3 in this case as: encapContentInfo eContentType is other than id-data (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_5(t *testing.T) {
	sd := signed_data_raw{}
	sd.Certificates = make([]certificate_choice, 1)
	sd.Certificates[0].V2AttrCert.SignatureValue.BitLength = 1
	sd.set_appropriate_version()
	assert.Equal(t, 4, sd.Version, "The version MUST be 4 in this case as: any version 2 attribute certificates are present (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_6(t *testing.T) {
	sd := signed_data_raw{}
	sd.Certificates = make([]certificate_choice, 1)
	sd.Certificates[0].Other.OtherCert = true
	sd.set_appropriate_version()
	assert.Equal(t, 5, sd.Version, "The version MUST be 5 in this case as: any certificates with a type of other are present (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_SetAppropriateVersion_7(t *testing.T) {
	sd := signed_data_raw{}
	sd.CRLs = make([]revocation_info_choice, 1)
	sd.CRLs[0].Other.OtherRevInfo = true
	sd.set_appropriate_version()
	assert.Equal(t, 5, sd.Version, "The version MUST be 5 in this case as: any crls with a type of other are present (see RFC5625 Section 5.1 Page 9)")
}

func Test_SignedData_GetFinalMessageDigest_1(t *testing.T) {
	si := signer_info_raw{}
	_, cerr := si.GetFinalMessageDigest(nil)
	assert.EqualValues(t, ERR_NO_CONTENT, cerr.Code())
}

func Test_SignedData_GetFinalMessageDigest_2(t *testing.T) {
	si := signer_info_raw{}
	si.DigestAlgorithm = algorithm_identifier{Algorithm: idSha1WithRSAEncryption}
	e := encapsulated_content_info{}
	e.EContent = []byte{}
	right_ans := from_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
	ans, cerr := si.GetFinalMessageDigest(&e)
	require.Nil(t, cerr)
	assert.Equal(t, right_ans, ans)
}

func Test_SignedData_GetFinalMessageDigest_3(t *testing.T) {
	si := signer_info_raw{}
	si.DigestAlgorithm = algorithm_identifier{Algorithm: idSha1}
	e := encapsulated_content_info{}
	e.EContent = []byte("hi")
	right_ans := from_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
	ans, cerr := si.GetFinalMessageDigest(&e)
	require.Nil(t, cerr)
	assert.NotEqual(t, right_ans, ans)
}

func Test_SignedData_GetFinalMessageDigest_4(t *testing.T) {
	si := signer_info_raw{}
	si.DigestAlgorithm = algorithm_identifier{Algorithm: idSha1}
	si.SignedAttrs = make([]attribute, 0)
	e := encapsulated_content_info{}
	e.EContent = []byte{}
	right_ans := from_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
	right_ans2 := from_hex("27062FF2EB5D9D81B8B050D3CF4D1323A717611B")
	si.SetContentTypeAttr(idData)
	ans, cerr := si.GetFinalMessageDigest(&e)
	require.Nil(t, cerr)
	assert.Equal(t, right_ans, si.SignedAttrs[1].Values[0])
	assert.Equal(t, right_ans2, ans)
}

func Test_SignedData_GetFinalMessageDigest_5(t *testing.T) {
	si := signer_info_raw{}
	si.DigestAlgorithm = algorithm_identifier{Algorithm: idSha256}
	e := encapsulated_content_info{}
	e.EContent = []byte("Lorem Ipsum Dolor Est\n")
	right_ans := from_hex("22C74533DA0788488A861D37330AE642F41BB1E1070B31EF4A3EF62D454129A3")
	ans, cerr := si.GetFinalMessageDigest(&e)
	require.Nil(t, cerr)
	assert.Equal(t, right_ans, ans)
}

func Test_SignerInfo_SetSigningTime(t *testing.T) {
	si := signer_info_raw{}
	le_time := time.Unix(1533132660, 0).UTC()
	si.SetSigningTime(le_time)
	right_ans := []attribute{
		attribute{
			Type:   idSigningTime,
			Values: []interface{}{le_time},
		},
	}
	assert.Equal(t, right_ans, si.SignedAttrs)
}

func Test_SignerInfo_Sign(t *testing.T) {
	var ok bool

	// beltrano test key
	privkey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: big.NewInt(0),
			E: 65537,
		},
		D: big.NewInt(0),
		Primes: []*big.Int{
			big.NewInt(0),
			big.NewInt(0),
		},
	}
	privkey.N, ok = privkey.N.SetString("00a3c8e4f6d0a3307f828ac6349d10007411fe0788f47c4f177e14c949e40c449aa50da5a47a2ce6e5178e80430dfcd2b84c44900bb897e21887d592930c47672dc719e1d1d70fd3064d3f8879642a0b31b9c076a919b0af1ebbaa26d8d214294cde045b8bc500a8aa7a2be79e68399c57dcc37899f29d0b946e8bd4f3e775829bffebc2158e66697ce03de413e2d280ef7f1c19da7c7aced419967d4261b67f830e3968472ffd899c4c1e8512bd5717a4663e8e94d16fefbf5b48b5c7060e146aeb93bd50ce204c6240f5e81567ccb24c55858b3379a46867bad93228314f539f267b5e5e0de3944e5d3948f5f3d5241594d2e0be3ec5c0d4268928418971ccad", 16)
	require.True(t, ok)
	privkey.D, ok = privkey.D.SetString("65fb460e24d527f28d6f29814336de81675e9c847b6f17b4520e5153900acf80d73b0b23c1eb498de64015bf2aeb7cadc2d78235ba27e06153daf91c54adf521fcf231b8fe475d27745c15f7381631c83198148ab07362672985061145a5c61d95b472e831af7a56442228636b144c342d430d4a1656110ac8568b2f9fb47cb0f4c992e11015a10a454e16007b4c94369b920958a0139e2a388d8e35b25f61756c4b6a8e16ebedb41d1332a2aff561eca659f1314c1897437f3e6f047d980678259e95d14918bcd715c765e701f9b158b08324f98bcd459395fec1608605118fdc031fe1f603d68f2f5fbe4876328735f46f2cda18649d613004fef6a2112c61", 16)
	require.True(t, ok)
	privkey.Primes[0], ok = privkey.Primes[0].SetString("00d5c955fd8aae12160cec873d18dec677e0a391e17e7fa1ee7500ee3af2df12f13c2bcdba8d9bd60ed432875f1093a2bbd135ae23ec52c543b53d4fd6262fa812df1befa42f806eb39843bae48d18ef28fd3bae672fac45197390c801c9649d3fa8e75ed7783411eebbea6f6cf704e3361400ff90ac5c203f6e36450ed94fe9e9", 16)
	require.True(t, ok)
	privkey.Primes[1], ok = privkey.Primes[1].SetString("00c420072341ba87b1f76b505d26c12c812b2606020df879edf697894cc031e4f3a665b70be017e25d5d7a348eb6de9bdc2d8827ae3c1bbbbccebd9ff3ab2998ed9b57410cc1172fe259221f25fa18a98239a4d300372e76a6340bdfa987deb85feb784ed0ab1780189d81babccf330d186b0337e677a07a31ee04568326a04e25", 16)
	require.True(t, ok)
	require.Nil(t, privkey.Validate())

	// Create simple message
	si := signer_info_raw{}
	si.SignatureAlgorithm = algorithm_identifier{Algorithm: idRSAEncryption}
	si.DigestAlgorithm = algorithm_identifier{Algorithm: idSha256}
	si.SetContentTypeAttr(idData)
	si.SetSigningTime(time.Date(2018, 8, 1, 20, 23, 11, 0, time.UTC))
	e := encapsulated_content_info{}
	e.EContentType = idData
	e.EContent = []byte("Lorem Ipsum Dolor Est\n")

	// Sign
	_, cerr := si.GetFinalMessageDigest(&e)
	require.Nil(t, cerr)
	require.Nil(t, si.Sign(&privkey))

	right_ans := from_hex("36A1E19C 87C38ECF A2E6B376 F3BE9927 F236123C 097A322F F5DC4CCD 1B4459A3 F15C7DF3 65135043 4714B998 47BD8E6D 0C7EEF59 F567F6B3 BE54AB32 DCB36EBA AD312B86 A51DC9CA 9E2F31C0 EC389233 79B94B1C A20D2013 1ED38EA8 C64A79A9 8A4BA28E D01F4125 3979E3AE E731AB40 43AF14ED 6F6865E5 A6A71D31 A9358B8F 0E981BAE 41939A87 E3A78AF7 37A63386 BC562F0C A37B29B8 9FC413A6 2458291A 1D91CE91 199F608D 3D65FF56 C75138D1 9052E5EF CC9FE77F 5FD063E8 C138134F 19F88677 8C5CE006 BEF45BD9 00FD8FE6 8848A4D9 2F544327 69E30A13 4E9A2A3B 767B5B23 4FB06663 B6B51BA4 0CDDE211 EC724145 8022C763 45F4B4D6 73085146")
	assert.Equal(t, right_ans, si.Signature)
}
