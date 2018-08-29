package libICP

import (
	"math/big"
	"testing"

	"github.com/OpenICP-BR/asn1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_decrypt_PbeWithSHAAnd3KeyTripleDES_CBC(t *testing.T) {
	ans, err := decrypt_PbeWithSHAAnd3KeyTripleDES_CBC(conv_password("beltrano"), 2048, beltrano_cert_salt, beltrano_cert_enc)
	require.Nil(t, err)
	assert.Equal(t, beltrano_cert_dec, ans)
}

func Test_encrypt_PbeWithSHAAnd3KeyTripleDES_CBC(t *testing.T) {
	ans, err := encrypt_PbeWithSHAAnd3KeyTripleDES_CBC(conv_password("beltrano"), 2048, beltrano_cert_salt, beltrano_cert_dec)
	require.Nil(t, err)
	assert.Equal(t, beltrano_cert_enc, ans)
}

func Test_pfx_raw_Marshal(t *testing.T) {
	pack := certificate_pack{}
	pack.SignatureAlgorithm.Algorithm = idRSAEncryption
	pack.TBSCertificate.Signature.Algorithm = idRSAEncryption
	pack.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm = idRSAEncryption
	pack.TBSCertificate.SerialNumber = big.NewInt(10)
	_, cerr := asn1.Marshal(pack.TBSCertificate)

	require.Nil(t, cerr)
	key, _, _ := new_rsa_key(2048)
	dat, cerr := marshal_pfx("beltrano", pack, key)
	require.Nil(t, cerr)
	assert.NotNil(t, dat)
}

func Test_NewPFXFromDER(t *testing.T) {
	_, cerr := NewPFXFromDER(beltrano_cert, "beltrano")
	require.Nil(t, cerr)
}

var beltrano_cert_salt []byte = from_hex("676F447E2F72BA4D")
var beltrano_cert_enc []byte = from_hex("AC7B8B835A6EFE1AA7E58148B2708239A5AFED975375A972DF9CCD5F62B81F4B778E15F240AEE9A23A780F346A9B407EE3F44665AD0A1192DBE47EF431B107CC504E2FD2706C1E80E2EB3415E5C76CC38548F78DD1576E0415F28459DD26A5FFEA9A5A0820B81421CD6EF4017BB8789E4D04A4BD9A645676AAA8893AC5A62C0DFB210C1D20B7104220F2E27942EAFEB8D431262A44F430CD73EFF5283583D6653F86404EBB4007E892A4B93EB33F8205AEC6CC8DCCC26C75EB256EB8F87C40FE6CB8B02E4D6759E2F3B52ABBF670233157972536EB8B1A1206D26467A80DFB3DDCAA1B81E5F8154C1C88991522A2EFCF977D8AA6401557B1C19DD9D7A53F44D3F2821AA16F3284EF0F4338478239FAF86FCF6AE45D0CFFE82BB1A92AD5806D98F8F53A7EFF890A7D0A10F9C97A79D4F0018EDA312EED361101457DC20A874296981AE23C5022BA405B5D204D709C84BE1CB2EE4A4F9488A72DD6807A6E4ED4600B939CDB975ADD5A789A5F6946542E75A1C1634B46F11C84AC8AB8132CDE45CFE2DB9B0D2767711BE1E6BA7C42F5D66BA7E91D512138F4ED3C2B1B9E62AB54B1589EA043F7AE3552ACF8C7657655DF7FFC9FBCB0627F713C34C303E5E31C59CB38642A375906BD8D99D6B6077EA589BC7E59540BD63287FF498A29533E4926F378DFD44DA3064E28BA89FF324F830866A99D38103A783D83FB09544E08D9F7C5D94FBBFFFE6DA5F9ACAF85C3DB2802F4798D7AB5A69CCE43EEB6011849AC9FB88A1974FBB020F5127059A5DF01CE540E2558EC7157B07E46DC955C440A5DAF2109DA3D35E34A16D0562121BA9B908ED223CB5A16D90C801334CDF5E9A063FF40D502918E999BE963418FBD62FB81719003F177249E9B54F6C0D8E8EB475D642D4794DC49A2F4D6BA3C2DDE90AF438E9F214E4FAD031E308A1D5BA4377BEB08F59ACC6185E7B354F41E54E8ED4DA48C9BA814222167DFB3B6EC0EB46E648765E9FFD9F63E0420F048917F0CF5E93274DA3C469B9CC8E4BE15AF3B49A43B93BC8501A96BC33DFDA972FD4028B9337398BCB90A85CDA1EB9ED759D571298AA524D323A653CB5FECD2ACAFD4E2EF48D9E026A0D20261FB2E61778CC5203A8FC24D77DA69D56DBD386AC80286F52E1BE659C350C1C95C17DB5A5A00EEE7AE00B4C3ABFF2AE4E0590A8F1F105B1529CE266614B23827707EF8D445D7587213A91057DE35A06DD7A1E7C0B3467A70BC0B2079B933DC6789CB1D858DCD95E60E168FFE1D9B3F141A92986BEC154600EDE59D8B62189ACF5F83321B183DF7C7B7A203474E79C8CD0A5AB3AA848F97861037B69E42023F3CED744E128CB1E4DD5F06930D7ACCD13FC75BD286DF509C51C0E9620D5883B5EFF2D16109477E0DD9FF8B9933674BD37ABB4BADCB673AB02A01CFD2FD77CECAC53DC0EA232ADC87BF52084B2D87F11D5B52568F1F79E513C812565D04F812186C5197F6E07344BA796E2987757CFDF4AAD9FBAF098D7BABF0642DFC43C24B0A5A9327FC76837C06652D034507E095E6963767413D515A0C1C45EB5DB59A69A71040BA478C5220ABE1CDC01984BBA0E28FCB72926867526D482B5D779A1C53AE3781A799BE69CE2E32B3FBA9015E93226409451B79FD45D02EB201BB58F2814D7BCD46C0596EA2FE68DD68F59ED4C05F7C82606F2BD445B3CB3E9D93EC03FD6111823125DF732DF90FD9A1E775185D755B79DAA5748F")
var beltrano_cert_dec []byte = from_hex("308204BD020100300D06092A864886F70D0101010500048204A7308204A30201000282010100A3C8E4F6D0A3307F828AC6349D10007411FE0788F47C4F177E14C949E40C449AA50DA5A47A2CE6E5178E80430DFCD2B84C44900BB897E21887D592930C47672DC719E1D1D70FD3064D3F8879642A0B31B9C076A919B0AF1EBBAA26D8D214294CDE045B8BC500A8AA7A2BE79E68399C57DCC37899F29D0B946E8BD4F3E775829BFFEBC2158E66697CE03DE413E2D280EF7F1C19DA7C7ACED419967D4261B67F830E3968472FFD899C4C1E8512BD5717A4663E8E94D16FEFBF5B48B5C7060E146AEB93BD50CE204C6240F5E81567CCB24C55858B3379A46867BAD93228314F539F267B5E5E0DE3944E5D3948F5F3D5241594D2E0BE3EC5C0D4268928418971CCAD02030100010282010065FB460E24D527F28D6F29814336DE81675E9C847B6F17B4520E5153900ACF80D73B0B23C1EB498DE64015BF2AEB7CADC2D78235BA27E06153DAF91C54ADF521FCF231B8FE475D27745C15F7381631C83198148AB07362672985061145A5C61D95B472E831AF7A56442228636B144C342D430D4A1656110AC8568B2F9FB47CB0F4C992E11015A10A454E16007B4C94369B920958A0139E2A388D8E35B25F61756C4B6A8E16EBEDB41D1332A2AFF561ECA659F1314C1897437F3E6F047D980678259E95D14918BCD715C765E701F9B158B08324F98BCD459395FEC1608605118FDC031FE1F603D68F2F5FBE4876328735F46F2CDA18649D613004FEF6A2112C6102818100D5C955FD8AAE12160CEC873D18DEC677E0A391E17E7FA1EE7500EE3AF2DF12F13C2BCDBA8D9BD60ED432875F1093A2BBD135AE23EC52C543B53D4FD6262FA812DF1BEFA42F806EB39843BAE48D18EF28FD3BAE672FAC45197390C801C9649D3FA8E75ED7783411EEBBEA6F6CF704E3361400FF90AC5C203F6E36450ED94FE9E902818100C420072341BA87B1F76B505D26C12C812B2606020DF879EDF697894CC031E4F3A665B70BE017E25D5D7A348EB6DE9BDC2D8827AE3C1BBBBCCEBD9FF3AB2998ED9B57410CC1172FE259221F25FA18A98239A4D300372E76A6340BDFA987DEB85FEB784ED0AB1780189D81BABCCF330D186B0337E677A07A31EE04568326A04E2502818100B21D9EA1310BBA51D8CEB0163D444E42CE4C395C9012328E03B994C2545B7AE2B5E920EC8ED309532D8433B9068C9A86B4D56E92CB70629DF8C06E65D346DD576BBF50B7904406F766A2F7713805502CEC5EEEFD5580C7C95EB97F89CD8B20604B8F093BA81069E86773F905E600927519D1831BBC1EBD575BB1A773A9A6A5110281800A0981940257237EAE24E5D5FE97C0495405FC24BAC64EA729099453433ACA76D5BB3AE4F6B1023AB8FFFA149BB344D2BDD9CBFE14C16E983914674D372347DA512AE3FF5D1A6CAEEED4DA373D5769C56A61CF12A1C054FE2887BB08981583E614CCF16BA875E96E59113C97511B51BE402BC7FE997CB3043F2425B14C96C3A902818000C05E4255A606B356686EAE68DFB0B0138CCBA284A244FF43B5FBCEBC416D85259EAF48575408C1FBB4B9155E01A27F515B8D2A0AEA5B21960CC9F16FC36142C3279A08DB304449B743A9663AEA1807857473C21C740BE92188933965D7EBC0ED87CDAA0572FF3D41DB491CB09606B8FABCA644088CA7091044400DEB00529F")
var beltrano_cert []byte = from_hex("30820ba102010330820b6706092a864886f70d010701a0820b5804820b5430820b503082060706092a864886f70d010706a08205f8308205f4020100308205ed06092a864886f70d010701301c060a2a864886f70d010c0106300e0408e96d07052a58b2e302020800808205c005a2c39ed18967d48f11263cdba8e4be90b2f03f1f22df60dbf16ecfc4b6814137bf3928e353a531a2850aeb2a22dba2a7ade26b9fae26e00dd10dd80216c1f0dca54e9193921c8ada8bdd6f5d2b232cd6385e068578cd1c79b14909392a576cf6cc636e52efbea9cab3adc5a9371e39101bfc5a8dae97c54376fa08d55b6dffbe781d04a406d5639e26ef583729b1c040f35461474bc2cf5401a3410149f3553f32273f7a7a2179f81a6d54a8e6c75985336c19b440dab950eacb6559097b2875318d7e5fdeeaad20b45ef7dae6dc7f665a4233a6b182f590dd04e927d09a2c7f1130aebc385d2523b343bfdab617e0c0dec1683a73ff69525c604e0572d1e575f75d49ce0d6497810c58e493deef1f72b31b4aca15a307efc7e79e128f50869097f69a9d830a567bb92bb0624206e9c8f732bb8ad54393b1c66bd92682abcdcc1de88feeec5edcb675b6c7c5ef2d80da675e4f3d55eab41f48290fd3bbedeffd0baa2c55afb2a31ce448de3e1b781fa3adb030836c6cd856c594d8a2732cf352a3825c96ce48726fb49e44541e1bdfcb12927a3653e7786ac8bc52c33f3672e4756793ce8ea62bf45ca2102bac43824901fce72383920bbec7a9c4d0cf917564f7ea2af229ed118d1b472b61a036e39feb9d994affee598143f01b20360f2017337fc9fb8304021982133f0c9f1f87b4d7de4b8bffc6a2f7b9aaf5d7aad46231eed209f72af80c2f1a4d4576daec178aeabb1b1885454424539bb58c8f45943028aa26d44de2462b1cc4b0d998de2e79807e8ae66056e65de1ed316bd8e29af35740ee53f4b4c109f959a594e9f06ec80c9d0d03c13230c527f2616799cce5eabb68cdd877603988d8a3d5177e58d9b4ac20c3c027731b544edb0eebcb589e1f066e1a458d908b256b9e42ff0a911e5913ef6cd3391d7b0be5ce57d945f661a2966e1c5d2b068c49abd4a1e554722e74633838f2800506ac0d1d182c303538a98815b57d79193d78ad4e6746fd94502d3ef1a5b68b371da946dba8e250bf33d55a3f75c64c08588b8b4ac14501950bae37c306679348c642f499cc34534fe279e19781aa505a42c1d4901933788a5eb6a7950f271f73c72ef85480006cfedc2b55ee65287ad658dd0a4a923f55b8c95a88bf02fee46f3194da6e6e1676e336a6ad53de5ee7f29e6fbd547497308edb56aecbca335bd02e5102ff010b2f047d3dbc956545cbb2e9e3bca61a0597972b038e225a988eb9820b7fcf41fe01b779c88e470c2f51545636ab91a40fe7d9cc66bf197b4cb0fa92aa7097f19e88d71ed0de41595c9f032936cd285244f57e6566ab019efafcd75ab7aa42984448121ab9c5191637fefc78392238a3a92b5ff1657b76c74fc3d7bb561278a60c339802eca2dc1e59df994a0495a92fc7ebe048c07bbdcef786d888934e9b2ee9db101da5c2bac25f95aff0b97b73de17402edcd72ddfbb1c142f7b32479837fd8936f4419ee3a32ffb7b63b6897fc10cff913ff05c59121aef2a8c651b7c6c1bd8cf5b3b65919a7a51c7be7b2f9202e35f8d0dfddf6036846af7f1500a2c9dc7df824851bbddb64cfd2bdf21e49a396b0140474e5322db0a5011bea5d5df153c77248c51776c75be3962dabeb4aeefa65f6830a12dd00fa6bbddf9f79bbac61ca8218d11fb7c2c12799ed39f6d9d54eadb54f3b3a7e6ded75caadddd607cef7ad385ae7143eaa856d722153da424b03b1e26699fdf6ae1d9ac7400181f3eaece42c2c7e153d3502840c80f567dde6d45d4341e3fcbeb0dc2ab2d85c59a2f36fc904cc79d5dbb86e72171df4b63dd16c4cb9d7cb50650d35fc1b502bdc9dc9dbfa3649dd0d726fb0e23f44148aa040985b970dd89d9af95eb213c3e32b41b1393da3a74284bbd8661311e7951167c37b1e42170e9ef9aa44451c66034f5dd7dacfb1907b8be752dc3999ffc1bee8905fd1c87e87522dc510b5d8ffef922f4bc9ab116f8243bf5cb943235700039f5685ff64e374080812e83e3b7eec131d4a23cfe7b05e1b7b39f6d9d573dc8db36dc07500d37d19f722180dadecbd42941bf4dac0abc3082054106092a864886f70d010701a08205320482052e3082052a30820526060b2a864886f70d010c0a0102a08204ee308204ea301c060a2a864886f70d010c0103300e0408676f447e2f72ba4d02020800048204c8ac7b8b835a6efe1aa7e58148b2708239a5afed975375a972df9ccd5f62b81f4b778e15f240aee9a23a780f346a9b407ee3f44665ad0a1192dbe47ef431b107cc504e2fd2706c1e80e2eb3415e5c76cc38548f78dd1576e0415f28459dd26a5ffea9a5a0820b81421cd6ef4017bb8789e4d04a4bd9a645676aaa8893ac5a62c0dfb210c1d20b7104220f2e27942eafeb8d431262a44f430cd73eff5283583d6653f86404ebb4007e892a4b93eb33f8205aec6cc8dccc26c75eb256eb8f87c40fe6cb8b02e4d6759e2f3b52abbf670233157972536eb8b1a1206d26467a80dfb3ddcaa1b81e5f8154c1c88991522a2efcf977d8aa6401557b1c19dd9d7a53f44d3f2821aa16f3284ef0f4338478239faf86fcf6ae45d0cffe82bb1a92ad5806d98f8f53a7eff890a7d0a10f9c97a79d4f0018eda312eed361101457dc20a874296981ae23c5022ba405b5d204d709c84be1cb2ee4a4f9488a72dd6807a6e4ed4600b939cdb975add5a789a5f6946542e75a1c1634b46f11c84ac8ab8132cde45cfe2db9b0d2767711be1e6ba7c42f5d66ba7e91d512138f4ed3c2b1b9e62ab54b1589ea043f7ae3552acf8c7657655df7ffc9fbcb0627f713c34c303e5e31c59cb38642a375906bd8d99d6b6077ea589bc7e59540bd63287ff498a29533e4926f378dfd44da3064e28ba89ff324f830866a99d38103a783d83fb09544e08d9f7c5d94fbbfffe6da5f9acaf85c3db2802f4798d7ab5a69cce43eeb6011849ac9fb88a1974fbb020f5127059a5df01ce540e2558ec7157b07e46dc955c440a5daf2109da3d35e34a16d0562121ba9b908ed223cb5a16d90c801334cdf5e9a063ff40d502918e999be963418fbd62fb81719003f177249e9b54f6c0d8e8eb475d642d4794dc49a2f4d6ba3c2dde90af438e9f214e4fad031e308a1d5ba4377beb08f59acc6185e7b354f41e54e8ed4da48c9ba814222167dfb3b6ec0eb46e648765e9ffd9f63e0420f048917f0cf5e93274da3c469b9cc8e4be15af3b49a43b93bc8501a96bc33dfda972fd4028b9337398bcb90a85cda1eb9ed759d571298aa524d323a653cb5fecd2acafd4e2ef48d9e026a0d20261fb2e61778cc5203a8fc24d77da69d56dbd386ac80286f52e1be659c350c1c95c17db5a5a00eee7ae00b4c3abff2ae4e0590a8f1f105b1529ce266614b23827707ef8d445d7587213a91057de35a06dd7a1e7c0b3467a70bc0b2079b933dc6789cb1d858dcd95e60e168ffe1d9b3f141a92986bec154600ede59d8b62189acf5f83321b183df7c7b7a203474e79c8cd0a5ab3aa848f97861037b69e42023f3ced744e128cb1e4dd5f06930d7accd13fc75bd286df509c51c0e9620d5883b5eff2d16109477e0dd9ff8b9933674bd37abb4badcb673ab02a01cfd2fd77cecac53dc0ea232adc87bf52084b2d87f11d5b52568f1f79e513c812565d04f812186c5197f6e07344ba796e2987757cfdf4aad9fbaf098d7babf0642dfc43c24b0a5a9327fc76837c06652d034507e095e6963767413d515a0c1c45eb5db59a69a71040ba478c5220abe1cdc01984bba0e28fcb72926867526d482b5d779a1c53ae3781a799be69ce2e32b3fba9015e93226409451b79fd45d02eb201bb58f2814d7bcd46c0596ea2fe68dd68f59ed4c05f7c82606f2bd445b3cb3e9d93ec03fd6111823125df732df90fd9a1e775185d755b79daa5748f3125302306092a864886f70d01091531160414aefdec6e358a9f8439aed4d1d033e0436889ec8930313021300906052b0e03021a05000414eca413c492c0a302706470948c7b792f1a94f195040855e97d9dbe32cb2f02020800")
