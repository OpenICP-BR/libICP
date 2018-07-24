package icp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_EncapsulatedContentInfo_HashAs_1(t *testing.T) {
	ec := EncapsulatedContentInfo{}
	ec.EContent = []byte("The quick fox jumps over the lazy dog.")
	assert.False(t, ec.IsDetached())
	assert.True(t, ec.IsHashable())
	right_ans := []byte{0x82, 0xd5, 0x10, 0xa7, 0xaa, 0x67, 0x03, 0x65, 0x9f, 0xb9, 0x24, 0x3e, 0x3e, 0x6b, 0x1c, 0xb9, 0xa4, 0xf5, 0x1c, 0x04}

	ans, err := ec.HashAs(AlgorithmIdentifier{Algorithm: IdSha1WithRSAEncryption()})
	require.Nil(t, err)
	assert.Equal(t, right_ans, ans)
	ans, err = ec.HashAs(AlgorithmIdentifier{Algorithm: IdSha1WithRSAEncryption()})
	require.Nil(t, err)
	assert.Equal(t, right_ans, ans)
}

func Test_EncapsulatedContentInfo_HashAs_2(t *testing.T) {
	ec := EncapsulatedContentInfo{}
	ec.fallback_file = "../data/hash_test.txt"

	assert.True(t, ec.IsDetached())
	assert.True(t, ec.IsHashable())

	right_ans := []byte{0x82, 0xd5, 0x10, 0xa7, 0xaa, 0x67, 0x03, 0x65, 0x9f, 0xb9, 0x24, 0x3e, 0x3e, 0x6b, 0x1c, 0xb9, 0xa4, 0xf5, 0x1c, 0x04}

	ans, err := ec.HashAs(AlgorithmIdentifier{Algorithm: IdSha1WithRSAEncryption()})
	require.Nil(t, err)
	assert.Equal(t, right_ans, ans)
	ans, err = ec.HashAs(AlgorithmIdentifier{Algorithm: IdSha1WithRSAEncryption()})
	require.Nil(t, err)
	assert.Equal(t, right_ans, ans)
}

func Test_EncapsulatedContentInfo_HashAs_3(t *testing.T) {
	ec := EncapsulatedContentInfo{}
	_, err := ec.HashAs(AlgorithmIdentifier{})
	assert.EqualValues(t, ERR_UNKOWN_ALGORITHM, err.Code())
}

func Test_EncapsulatedContentInfo_SetFallbackFile_1(t *testing.T) {
	ec := EncapsulatedContentInfo{}
	cerr := ec.SetFallbackFile("../data/hash_test.txt")
	assert.Nil(t, cerr)
}

func Test_EncapsulatedContentInfo_SetFallbackFile_2(t *testing.T) {
	ec := EncapsulatedContentInfo{}
	cerr := ec.SetFallbackFile("data/hash_test.txt")
	assert.EqualValues(t, ERR_FILE_NOT_EXISTS, cerr.Code())
}
