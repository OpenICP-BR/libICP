package icp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_oid2str_key(t *testing.T) {
	assert.Equal(t, "C", oid2str_key(idCountryName()))
	assert.Equal(t, "S", oid2str_key(idStateOrProvinceName()))
	assert.Equal(t, "L", oid2str_key(idLocalityName()))
	assert.Equal(t, "O", oid2str_key(idOrganizationName()))
	assert.Equal(t, "OU", oid2str_key(idOrganizationalUnitName()))
	assert.Equal(t, "CN", oid2str_key(idCommonName()))
}
