package icp

import "encoding/asn1"

type nameT struct {
	RawContent  asn1.RawContent
	RDNSequence []atv_SET
}

// Also known as RelativeDistinguishedName
type atv_SET struct {
	RawContent asn1.RawContent
	Type       asn1.ObjectIdentifier
	Value      interface{}
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
