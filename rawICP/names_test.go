package rawICP

import (
	"testing"

	"github.com/gjvnq/asn1"
	"github.com/stretchr/testify/assert"
)

func Test_Name_String_1(t *testing.T) {
	n := Name{}
	assert.Equal(t, "", n.String())
}

func Test_Name_String_2(t *testing.T) {
	n := Name{
		RDN_SET{
			ATV{Type: IdEmailName(), Value: "a@b.com"},
		},
		RDN_SET{
			ATV{Type: IdCountryName(), Value: "BR"},
		},
		RDN_SET{
			ATV{Type: IdStateOrProvinceName(), Value: "SP"},
		},
		RDN_SET{
			ATV{Type: IdCommonName(), Value: "Random Cert"},
		},
		RDN_SET{
			ATV{Type: asn1.ObjectIdentifier{1, 2}, Value: "First unknown oid"},
		},
		RDN_SET{
			ATV{Type: asn1.ObjectIdentifier{1, 3, 840}, Value: "Second unkown oid"},
		},
	}
	assert.Equal(t, "C=BR/S=SP/CN=Random Cert/EMAIL=a@b.com/1.2=First unknown oid/1.3.840=Second unkown oid", n.String())
}

func Test_Name_String_3(t *testing.T) {
	n := Name{
		RDN_SET{
			ATV{Type: asn1.ObjectIdentifier{1, 2}, Value: "First unknown oid"},
		},
		RDN_SET{
			ATV{Type: asn1.ObjectIdentifier{1, 3, 840}, Value: "Second unkown oid"},
		},
	}
	assert.Equal(t, "1.2=First unknown oid/1.3.840=Second unkown oid", n.String())
}
