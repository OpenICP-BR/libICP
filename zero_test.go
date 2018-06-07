package icp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_IsZeroOfUnderlyingType_1(t *testing.T) {
	assert.True(t, IsZeroOfUnderlyingType(0), "")
}

func Test_IsZeroOfUnderlyingType_2(t *testing.T) {
	assert.False(t, IsZeroOfUnderlyingType(1), "")
}

func Test_IsZeroOfUnderlyingType_3(t *testing.T) {
	var v []int
	assert.True(t, IsZeroOfUnderlyingType(v), "")
}

func Test_IsZeroOfUnderlyingType_4(t *testing.T) {
	var v []int
	v = make([]int, 0)
	assert.False(t, IsZeroOfUnderlyingType(v), "")
}

func Test_IsZeroOfUnderlyingType_5(t *testing.T) {
	sd := SignedDataT{}
	assert.True(t, IsZeroOfUnderlyingType(sd), "")
}

func Test_IsZeroOfUnderlyingType_6(t *testing.T) {
	sd := SignedDataT{}
	sd.EncapContentInfo.EContent = make([]byte, 0)
	assert.False(t, IsZeroOfUnderlyingType(sd), "")
}