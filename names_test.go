package libICP

import (
	"testing"

	"github.com/gjvnq/asn1"
	"github.com/stretchr/testify/assert"
)

func Test_Name_String_1(t *testing.T) {
	n := nameT{}
	assert.Equal(t, "", n.String())
}

func Test_Name_String_2(t *testing.T) {
	n := nameT{
		rdn_set{
			atv{Type: idEmailName, Value: "a@b.com"},
		},
		rdn_set{
			atv{Type: idCountryName, Value: "BR"},
		},
		rdn_set{
			atv{Type: idStateOrProvinceName, Value: "SP"},
		},
		rdn_set{
			atv{Type: idCommonName, Value: "Random Cert"},
		},
		rdn_set{
			atv{Type: asn1.ObjectIdentifier{1, 2}, Value: "First unknown oid"},
		},
		rdn_set{
			atv{Type: asn1.ObjectIdentifier{1, 3, 840}, Value: "Second unkown oid"},
		},
	}
	assert.Equal(t, "C=BR/S=SP/CN=Random Cert/EMAIL=a@b.com/1.2=First unknown oid/1.3.840=Second unkown oid", n.String())
}

func Test_Name_String_3(t *testing.T) {
	n := nameT{
		rdn_set{
			atv{Type: asn1.ObjectIdentifier{1, 2}, Value: "First unknown oid"},
		},
		rdn_set{
			atv{Type: asn1.ObjectIdentifier{1, 3, 840}, Value: "Second unkown oid"},
		},
	}
	assert.Equal(t, "1.2=First unknown oid/1.3.840=Second unkown oid", n.String())
}
