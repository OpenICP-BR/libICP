package icp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isZeroOfUnderlyingType_1(t *testing.T) {
	assert.True(t, isZeroOfUnderlyingType(0), "")
}

func Test_isZeroOfUnderlyingType_2(t *testing.T) {
	assert.False(t, isZeroOfUnderlyingType(1), "")
}

func Test_isZeroOfUnderlyingType_3(t *testing.T) {
	var v []int
	assert.True(t, isZeroOfUnderlyingType(v), "")
}

func Test_isZeroOfUnderlyingType_4(t *testing.T) {
	var v []int
	v = make([]int, 0)
	assert.False(t, isZeroOfUnderlyingType(v), "")
}

func Test_isZeroOfUnderlyingType_5(t *testing.T) {
	sd := signedDataT{}
	assert.True(t, isZeroOfUnderlyingType(sd), "")
}

func Test_isZeroOfUnderlyingType_6(t *testing.T) {
	sd := signedDataT{}
	sd.EncapContentInfo.EContent = make([]byte, 0)
	assert.False(t, isZeroOfUnderlyingType(sd), "")
}
