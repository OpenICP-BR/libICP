package rawICP

import "github.com/gjvnq/asn1"

func IdRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
}

func IdSha1() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
}

func IdSha256() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
}

func IdSha384() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
}

func IdSha512() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
}

func IdSha224() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
}

func IdSha512_224() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 5}
}

func IdSha512_256() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 6}
}

func IdSha3_224() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 7}
}

func IdSha3_256() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}
}

func IdSha3_384() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}
}

func IdSha3_512() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10}
}

func IdMd2WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
}

func IdMd4WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 3}
}

func IdMd5WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
}

func IdSha1WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
}

func IdSha256WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
}

func IdSha384WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
}

func IdSha512WithRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
}

func IdSubjectKeyIdentifier() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 14}
}

func IdAuthorityKeyIdentifier() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 35}
}

func IdCeBasicConstraints() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 19}
}

func IdCeKeyUsage() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 15}
}

func IdCeCRLDistributionPoint() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 31}
}

// Returns the an ObjectIdentifier for id-ct-contentInfo { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 6 }
func IdCtContentInfo() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 6}
}

// Returns the an ObjectIdentifier for id-contentType { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) 3 }
func IdContentType() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
}

// Returns the an ObjectIdentifier for id-messageDigest { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) 4 }
func IdMessageDigest() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
}

// Returns the an ObjectIdentifier for id-signingTime { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) 5 }
func IdSigningTime() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
}

// Returns the an ObjectIdentifier for id-countersignature { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) 6 }
func IdCounterSignature() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
}

// Returns the an ObjectIdentifier for id-data { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }
func IdData() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
}

// Returns the an ObjectIdentifier for countryName
func IdCountryName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 6}
}

// Returns the an ObjectIdentifier for stateOrProvinceName
func IdStateOrProvinceName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 8}
}

// Returns the an ObjectIdentifier for localityName
func IdLocalityName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 7}
}

// Returns the an ObjectIdentifier for organizationName
func IdOrganizationName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 10}
}

// Returns the an ObjectIdentifier for organizationalUnitName
func IdOrganizationalUnitName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 11}
}

// Returns the an ObjectIdentifier for commonName
func IdCommonName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 3}
}

// Returns the an ObjectIdentifier for id-signedData { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
func IdSignedData() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
}

// Only for compatibility reasons. (From PKCS#9)
func IdEmailName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
}

func OID_Key2String(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(IdCountryName()):
		return "C"
	case oid.Equal(IdStateOrProvinceName()):
		return "S"
	case oid.Equal(IdLocalityName()):
		return "L"
	case oid.Equal(IdOrganizationName()):
		return "O"
	case oid.Equal(IdOrganizationalUnitName()):
		return "OU"
	case oid.Equal(IdCommonName()):
		return "CN"
	case oid.Equal(IdEmailName()):
		return "EMAIL"
	default:
		return oid.String()
	}
}
