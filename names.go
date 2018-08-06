package libICP

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gjvnq/asn1"
)

type Name []RDN_SET
type RDN_SET []ATV
type ATV struct {
	RawContent asn1.RawContent
	Type       asn1.ObjectIdentifier
	Value      interface{}
}

// Returns a copy/new map from a name.
func (this Name) Map() map[string]string {
	m := make(map[string]string)
	for _, item := range this {
		k := OID_Key2String(item[0].Type)
		m[k] = fmt.Sprintf("%s", item[0].Value)
	}
	return m
}

// Remvove both CR and LF from a given string
func RemoveNewLines(s string) string {
	s = strings.Replace(s, "\r", "", -1)
	s = strings.Replace(s, "\n", "", -1)
	return s
}

// Returns a name as a single line string. Ex: "C=BR/O=ICP-Brasil/OU=Autoridade Certificadora Raiz Brasileira v2/CN=AC CAIXA v2" Unknown OIDs will always be included in order.
func (this Name) String() string {
	// Prepare stuff
	ans := ""
	first := true
	m := this.Map()
	order := []string{"C", "S", "L", "O", "OU", "CN", "EMAIL"}
	// Add each element in the prefered order
	for _, k := range order {
		if v, ok := m[k]; ok {
			if !first {
				ans += "/"
			}
			ans += k + "=" + RemoveNewLines(v)
			delete(m, k)
			first = false
		}
	}
	// Sort remaining keys
	keys := make([]string, 0, len(m))
	for k, _ := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Add any remaining elements
	for _, k := range keys {
		v := m[k]
		if !first {
			ans += "/"
		}
		ans += k + "=" + RemoveNewLines(v)
		first = false
	}

	return ans
}

type AnotherName struct {
	RawContent asn1.RawContent
	TypeId     asn1.ObjectIdentifier
	Value      interface{} `asn1:"tag:0,explicit"`
}

type EDIPartyName struct {
	RawContent   asn1.RawContent
	NameAssigner DirectoryString `asn1:"tag:0,optional"`
	PartyName    DirectoryString `asn1:"tag:1"`
}

type DirectoryString struct {
	PrintableString string `asn1:"printable,optional,omitempty"`
	UTF8String      string `asn1:"utf8,optional,omitempty"`
	OtherString     string `asn1:"utf8,optional,omitempty"`
}

type BuiltInDomainDefinedAttribute struct {
	Type  string `asn1:"printable"`
	Value string `asn1:"printable"`
}

type ExtensionAttribute struct {
	Type  int         `asn1:"tag:0"`
	Value interface{} `asn1:"tag:1"`
}

type OrAddress struct {
	RawContent                     asn1.RawContent
	BuiltInStandardAttributes      BuiltInStandardAttributes
	BuiltInDomainDefinedAttributes []BuiltInDomainDefinedAttribute `asn1:"optional"`
	ExtensionAttributes            []ExtensionAttribute            `asn1:"optional,set"`
}

type CountryName struct {
	RawContent        asn1.RawContent
	X121DccCode       string `asn1:"optional,omitempty"`
	Iso3166Alpha2Code string `asn1:"optional,omitempty,printable"`
}

type NumericOrPrintable struct {
	RawContent asn1.RawContent
	Numeric    string `asn1:"optional,omitempty"`
	Printable  string `asn1:"optional,omitempty,printable"`
}

// Use with `asn1:"set"`
type PersonalName struct {
	RawContent          asn1.RawContent
	Surname             string `asn1:"tag:0"`
	GivenName           string `asn1:"optional,tag:1"`
	Initials            string `asn1:"optional,tag:2"`
	GenerationQualifier string `asn1:"optional,tag:2"`
}

type BuiltInStandardAttributes struct {
	RawContent               asn1.RawContent
	CountryName              CountryName        `asn1:"optional,omitempty"`
	AdministrationDomainName NumericOrPrintable `asn1:"optional,omitempty,application,tag:2"`
	NetworkAddress           string             `asn1:"tag:0,optional,omitempty"`
	TerminalIdentifier       string             `asn1:"tag:1,optional,omitempty,printable"`
	PrivateDomainName        NumericOrPrintable `asn1:"tag:2,explicit,optional,omitempty"`
	OrganizationName         string             `asn1:"tag:3,optional,omitempty,printable"`
	NumericUserIdentifier    string             `asn1:"tag:4,optional,omitempty"`
	PersonalName             PersonalName       `asn1:"tag:5,optional,omitempty,set"`
	OrganizationalUnitNames  []string           `asn1:"tag:6,optional,omitempty,printable"`
}

type GeneralName struct {
	RawContent                asn1.RawContent
	OtherName                 AnotherName           `asn1:"tag:0,optional,omitempty"`
	RFC822Name                string                `asn1:"tag:1,ia5,optional,omitempty"`
	DNSName                   string                `asn1:"tag:2,ia5,optional,omitempty"`
	X400Address               OrAddress             `asn1:"tag:3,optional,omitempty"`
	DirectoryName             Name                  `asn1:"tag:4,optional,omitempty"`
	EdiPartyName              EDIPartyName          `asn1:"tag:5,optional,omitempty"`
	UniformResourceIdentifier string                `asn1:"tag:6,ia5,optional,omitempty"`
	IPAddress                 []byte                `asn1:"tag:7,optional,omitempty"`
	RegisteredID              asn1.ObjectIdentifier `asn1:"tag:8,optional,omitempty"`
}

type Holder struct {
	RawContent        asn1.RawContent
	BaseCertificateID IssuerAndSerial  `asn1:"optional,omitempty,tag:0"`
	EntityName        []GeneralName    `asn1:"optional,omitempty,tag:1"`
	ObjectDigestInfo  ObjectDigestInfo `asn1:"optional,omitempty,tag:2"`
}
