package icp

import (
	"encoding/asn1"
	"fmt"
)

// Returns the an ObjectIdentifier for countryName
func idCountryName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 6}
}

// Returns the an ObjectIdentifier for stateOrProvinceName
func idStateOrProvinceName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 8}
}

// Returns the an ObjectIdentifier for localityName
func idLocalityName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 7}
}

// Returns the an ObjectIdentifier for organizationName
func idOrganizationName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 10}
}

// Returns the an ObjectIdentifier for organizationalUnitName
func idOrganizationalUnitName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 11}
}

// Returns the an ObjectIdentifier for commonName
func idCommonName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 4, 3}
}

func oid2str_key(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(idCountryName()):
		return "C"
	case oid.Equal(idStateOrProvinceName()):
		return "S"
	case oid.Equal(idLocalityName()):
		return "L"
	case oid.Equal(idOrganizationName()):
		return "O"
	case oid.Equal(idOrganizationalUnitName()):
		return "OU"
	case oid.Equal(idCommonName()):
		return "CN"
	default:
		return oid.String()
	}
}

type nameT []rdnSET
type rdnSET []atv
type atv struct {
	RawContent asn1.RawContent
	Type       asn1.ObjectIdentifier
	Value      interface{}
}

func (this nameT) Map() map[string]string {
	m := make(map[string]string)
	for _, item := range this {
		k := oid2str_key(item[0].Type)
		m[k] = fmt.Sprintf("%s", item[0].Value)
	}
	return m
}

func (this nameT) String() string {
	// Prepare stuff
	ans := ""
	first := true
	m := this.Map()
	order := []string{"C", "S", "L", "O", "OU", "CN"}
	// Add each element in the prefered order
	for _, k := range order {
		if v, ok := m[k]; ok {
			if !first {
				ans += "/"
			}
			ans += k + "=" + v
			delete(m, k)
			first = false
		}
	}
	// Add any remaining elements
	for k, v := range m {
		ans += k + "=" + v
		delete(m, k)
	}

	return ans
}

type anotherNameT struct {
	RawContent asn1.RawContent
	TypeId     asn1.ObjectIdentifier
	Value      interface{} `asn1:"tag:0,explicit"`
}

type ediPartyNameT struct {
	RawContent   asn1.RawContent
	NameAssigner directoryStringT `asn1:"tag:0,optional"`
	PartyName    directoryStringT `asn1:"tag:1"`
}

type directoryStringT struct {
	PrintableString string `asn1:"printable,optional,omitempty"`
	UTF8String      string `asn1:"utf8,optional,omitempty"`
	OtherString     string `asn1:"utf8,optional,omitempty"`
}

type builtInDomainDefinedAttributeT struct {
	Type  string `asn1:"printable"`
	Value string `asn1:"printable"`
}

type extensionAttributeT struct {
	Type  int         `asn1:"tag:0"`
	Value interface{} `asn1:"tag:1"`
}

type orAddressT struct {
	RawContent                     asn1.RawContent
	BuiltInStandardAttributes      builtInStandardAttributesT
	BuiltInDomainDefinedAttributes []builtInDomainDefinedAttributeT `asn1:"optional"`
	ExtensionAttributes            []extensionAttributeT            `asn1:"optional,set"`
}

type countryNameT struct {
	RawContent        asn1.RawContent
	X121DccCode       string `asn1:"optional,omitempty"`
	Iso3166Alpha2Code string `asn1:"optional,omitempty,printable"`
}

type numericOrPrintableT struct {
	RawContent asn1.RawContent
	Numeric    string `asn1:"optional,omitempty"`
	Printable  string `asn1:"optional,omitempty,printable"`
}

// Use with `asn1:"set"`
type personalNameT struct {
	RawContent          asn1.RawContent
	Surname             string `asn1:"tag:0"`
	GivenName           string `asn1:"optional,tag:1"`
	Initials            string `asn1:"optional,tag:2"`
	GenerationQualifier string `asn1:"optional,tag:2"`
}

type builtInStandardAttributesT struct {
	RawContent               asn1.RawContent
	CountryName              countryNameT        `asn1:"optional,omitempty"`
	AdministrationDomainName numericOrPrintableT `asn1:"optional,omitempty,application,tag:2"`
	NetworkAddress           string              `asn1:"tag:0,optional,omitempty"`
	TerminalIdentifier       string              `asn1:"tag:1,optional,omitempty,printable"`
	PrivateDomainName        numericOrPrintableT `asn1:"tag:2,explicit,optional,omitempty"`
	OrganizationName         string              `asn1:"tag:3,optional,omitempty,printable"`
	NumericUserIdentifier    string              `asn1:"tag:4,optional,omitempty"`
	PersonalName             personalNameT       `asn1:"tag:5,optional,omitempty,set"`
	OrganizationalUnitNames  []string            `asn1:"tag:6,optional,omitempty,printable"`
}

type generalNameT struct {
	RawContent                asn1.RawContent
	OtherName                 anotherNameT          `asn1:"tag:0,optional,omitempty"`
	RFC822Name                string                `asn1:"tag:1,ia5,optional,omitempty"`
	DNSName                   string                `asn1:"tag:2,ia5,optional,omitempty"`
	X400Address               orAddressT            `asn1:"tag:3,optional,omitempty"`
	DirectoryName             nameT                 `asn1:"tag:4,optional,omitempty"`
	EdiPartyName              ediPartyNameT         `asn1:"tag:5,optional,omitempty"`
	UniformResourceIdentifier string                `asn1:"tag:6,ia5,optional,omitempty"`
	IPAddress                 []byte                `asn1:"tag:7,optional,omitempty"`
	RegisteredID              asn1.ObjectIdentifier `asn1:"tag:8,optional,omitempty"`
}

type holderT struct {
	RawContent        asn1.RawContent
	BaseCertificateID issuerSerialT     `asn1:"optional,omitempty,tag:0"`
	EntityName        []generalNameT    `asn1:"optional,omitempty,tag:1"`
	ObjectDigestInfo  objectDigestInfoT `asn1:"optional,omitempty,tag:2"`
}
