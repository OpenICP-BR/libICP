package icp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_idCtContentInfo(t *testing.T) {
	ans := "1.2.840.113549.1.9.16.1.6"
	assert.Equal(t, ans, idCtContentInfo().String(), "id-ct-contentInfo MUST be "+ans+" (see RFC5652 Section 3 Page 6)")
}

func Test_idData(t *testing.T) {
	ans := "1.2.840.113549.1.7.1"
	assert.Equal(t, ans, idData().String(), "id-data MUST be "+ans+" (see RFC5652 Section 4 Page 6)")
}
