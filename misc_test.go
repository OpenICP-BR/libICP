package libICP

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Version(t *testing.T) {
	assert.Equal(t, "0.0.1", Version())
}

func Test_NiceHex(t *testing.T) {
	b := []byte{0xAA, 0xFF, 0x1E}
	assert.Equal(t, "AA:FF:1E", nice_hex(b))
}

func Test_EncapsulatedContentInfo_AdjustForNoSigners(t *testing.T) {
	ec := encapsulated_content_info{}
	ec.AdjustForNoSigners()

	assert.Equal(t, idData, ec.EContentType, "see RFC 5652 Section 5.2 Page 11 Paragraph 2")
	assert.Nil(t, ec.EContent, "see RFC 5652 Section 5.2 Page 11 Paragraph 2")
}

func Test_IsZeroOfUnderlyingType_1(t *testing.T) {
	assert.True(t, is_zero_of_underlying_type(0), "")
}

func Test_IsZeroOfUnderlyingType_2(t *testing.T) {
	assert.False(t, is_zero_of_underlying_type(1), "")
}

func Test_IsZeroOfUnderlyingType_3(t *testing.T) {
	var v []int
	assert.True(t, is_zero_of_underlying_type(v), "")
}

func Test_IsZeroOfUnderlyingType_4(t *testing.T) {
	var v []int
	v = make([]int, 0)
	assert.False(t, is_zero_of_underlying_type(v), "")
}

func Test_IsZeroOfUnderlyingType_5(t *testing.T) {
	sd := SignedData{}
	assert.True(t, is_zero_of_underlying_type(sd), "")
}

func Test_IsZeroOfUnderlyingType_6(t *testing.T) {
	sd := SignedData{}
	sd.EncapContentInfo.EContent = make([]byte, 0)
	assert.False(t, is_zero_of_underlying_type(sd), "")
}
