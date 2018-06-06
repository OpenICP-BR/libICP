package icp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_IdCtContentInfo(t *testing.T) {
	ans := "1.2.840.113549.1.9.16.1.6"
	assert.Equal(t, ans, IdCtContentInfo().String(), "id-ct-contentInfo MUST be "+ans+" (see RFC5652 Section 3 Page 6)")
}

func Test_IdData(t *testing.T) {
	ans := "1.2.840.113549.1.7.1"
	assert.Equal(t, ans, IdData().String(), "id-data MUST be "+ans+" (see RFC5652 Section 4 Page 6)")
}
