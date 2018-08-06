package libICP

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_OID_Key2String(t *testing.T) {
	assert.Equal(t, "C", OID_Key2String(idCountryName))
	assert.Equal(t, "S", OID_Key2String(idStateOrProvinceName))
	assert.Equal(t, "L", OID_Key2String(idLocalityName))
	assert.Equal(t, "O", OID_Key2String(idOrganizationName))
	assert.Equal(t, "OU", OID_Key2String(idOrganizationalUnitName))
	assert.Equal(t, "CN", OID_Key2String(idCommonName))
	assert.Equal(t, "1.2.840.113549.1.7.1", OID_Key2String(idData))
}
