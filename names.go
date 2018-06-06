package icp

import "encoding/asn1"

type NameT struct {
	RawContent  asn1.RawContent
	RDNSequence []ATV_SET
}

// Also known as RelativeDistinguishedName
type ATV_SET struct {
	RawContent asn1.RawContent
	Type       asn1.ObjectIdentifier
	Value      interface{}
}

type AnotherNameT struct {
	RawContent asn1.RawContent
	TypeId     asn1.ObjectIdentifier
	Value      interface{} `asn1:"tag:0,explicit"`
}

type EDIPartyNameT struct {
	RawContent   asn1.RawContent
	NameAssigner DirectoryStringT `asn1:"tag:0,optional"`
	PartyName    DirectoryStringT `asn1:"tag:1"`
}

type DirectoryStringT struct {
	PrintableString string `asn1:"printable,optional,omitempty"`
	UTF8String      string `asn1:"utf8,optional,omitempty"`
	OtherString     string `asn1:"utf8,optional,omitempty"`
}

type BuiltInDomainDefinedAttributeT struct {
	Type  string `asn1:"printable"`
	Value string `asn1:"printable"`
}

type ExtensionAttributeT struct {
	Type  int         `asn1:"tag:0"`
	Value interface{} `asn1:"tag:1"`
}

type ORAddressT struct {
	RawContent                     asn1.RawContent
	BuiltInStandardAttributes      BuiltInStandardAttributesT
	BuiltInDomainDefinedAttributes []BuiltInDomainDefinedAttributeT `asn1:"optional"`
	ExtensionAttributes            []ExtensionAttributeT            `asn1:"optional,set"`
}

type CountryNameT struct {
	RawContent        asn1.RawContent
	X121DccCode       string `asn1:"optional,omitempty"`
	Iso3166Alpha2Code string `asn1:"optional,omitempty,printable"`
}

type NumericOrPrintableT struct {
	RawContent asn1.RawContent
	Numeric    string `asn1:"optional,omitempty"`
	Printable  string `asn1:"optional,omitempty,printable"`
}

// Use with `asn1:"set"`
type PersonalNameT struct {
	RawContent          asn1.RawContent
	Surname             string `asn1:"tag:0"`
	GivenName           string `asn1:"optional,tag:1"`
	Initials            string `asn1:"optional,tag:2"`
	GenerationQualifier string `asn1:"optional,tag:2"`
}

type BuiltInStandardAttributesT struct {
	RawContent               asn1.RawContent
	CountryName              CountryNameT        `asn1:"optional,omitempty"`
	AdministrationDomainName NumericOrPrintableT `asn1:"optional,omitempty,application,tag:2"`
	NetworkAddress           string              `asn1:"tag:0,optional,omitempty"`
	TerminalIdentifier       string              `asn1:"tag:1,optional,omitempty,printable"`
	PrivateDomainName        NumericOrPrintableT `asn1:"tag:2,explicit,optional,omitempty"`
	OrganizationName         string              `asn1:"tag:3,optional,omitempty,printable"`
	NumericUserIdentifier    string              `asn1:"tag:4,optional,omitempty"`
	PersonalName             PersonalNameT       `asn1:"tag:5,optional,omitempty,set"`
	OrganizationalUnitNames  []string            `asn1:"tag:6,optional,omitempty,printable"`
}

type GeneralNameT struct {
	RawContent                asn1.RawContent
	OtherName                 AnotherNameT          `asn1:"tag:0,optional,omitempty"`
	RFC822Name                string                `asn1:"tag:1,ia5,optional,omitempty"`
	DNSName                   string                `asn1:"tag:2,ia5,optional,omitempty"`
	X400Address               ORAddressT            `asn1:"tag:3,optional,omitempty"`
	DirectoryName             NameT                 `asn1:"tag:4,optional,omitempty"`
	EdiPartyName              EDIPartyNameT         `asn1:"tag:5,optional,omitempty"`
	UniformResourceIdentifier string                `asn1:"tag:6,ia5,optional,omitempty"`
	IPAddress                 []byte                `asn1:"tag:7,optional,omitempty"`
	RegisteredID              asn1.ObjectIdentifier `asn1:"tag:8,optional,omitempty"`
}
