package libICP

import "github.com/gjvnq/asn1"

var idRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
var idSha1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
var idSha256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
var idSha384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
var idSha512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
var idSha224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
var idSha512_224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 5}
var idSha512_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 6}
var idSha3_224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 7}
var idSha3_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}
var idSha3_384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}
var idSha3_512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10}
var idMd2WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
var idMd4WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 3}
var idMd5WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
var idSha1WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
var idSha256WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
var idSha384WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
var idSha512WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
var idSubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}
var idAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
var idCeBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
var idCeKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
var idCeCRLDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 31}
var idCtContentInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 6}
var idContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
var idMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
var idSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
var idCounterSignature = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
var idData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
var idCountryName = asn1.ObjectIdentifier{2, 5, 4, 6}
var idStateOrProvinceName = asn1.ObjectIdentifier{2, 5, 4, 8}
var idLocalityName = asn1.ObjectIdentifier{2, 5, 4, 7}
var idOrganizationName = asn1.ObjectIdentifier{2, 5, 4, 10}
var idOrganizationalUnitName = asn1.ObjectIdentifier{2, 5, 4, 11}
var idCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}
var idSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
var idEmailName = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func OID_Key2String(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(idCountryName):
		return "C"
	case oid.Equal(idStateOrProvinceName):
		return "S"
	case oid.Equal(idLocalityName):
		return "L"
	case oid.Equal(idOrganizationName):
		return "O"
	case oid.Equal(idOrganizationalUnitName):
		return "OU"
	case oid.Equal(idCommonName):
		return "CN"
	case oid.Equal(idEmailName):
		return "EMAIL"
	default:
		return oid.String()
	}
}