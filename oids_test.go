package libICP

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_OID_Key2String(t *testing.T) {
	assert.Equal(t, "C", oid_key2str(idCountryName))
	assert.Equal(t, "S", oid_key2str(idStateOrProvinceName))
	assert.Equal(t, "L", oid_key2str(idLocalityName))
	assert.Equal(t, "O", oid_key2str(idOrganizationName))
	assert.Equal(t, "OU", oid_key2str(idOrganizationalUnitName))
	assert.Equal(t, "CN", oid_key2str(idCommonName))
	assert.Equal(t, "1.2.840.113549.1.7.1", oid_key2str(idData))
}
