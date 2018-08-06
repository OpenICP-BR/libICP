package libICP

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_EncapsulatedContentInfo_HashAs_1(t *testing.T) {
	ec := encapsulated_content_info{}
	ec.EContent = []byte("The quick fox jumps over the lazy dog.")
	assert.False(t, ec.IsDetached())
	assert.True(t, ec.IsHashable())
	right_ans := []byte{0x82, 0xd5, 0x10, 0xa7, 0xaa, 0x67, 0x03, 0x65, 0x9f, 0xb9, 0x24, 0x3e, 0x3e, 0x6b, 0x1c, 0xb9, 0xa4, 0xf5, 0x1c, 0x04}

	ans, err := ec.HashAs(algorithm_identifier{Algorithm: idSha1WithRSAEncryption})
	require.Nil(t, err)
	assert.Equal(t, right_ans, ans)
	ans, err = ec.HashAs(algorithm_identifier{Algorithm: idSha1WithRSAEncryption})
	require.Nil(t, err)
	assert.Equal(t, right_ans, ans)
}

func Test_EncapsulatedContentInfo_HashAs_2(t *testing.T) {
	ec := encapsulated_content_info{}
	ec.fallback_file = "data/hash_test.txt"

	assert.True(t, ec.IsDetached())
	assert.True(t, ec.IsHashable())

	right_ans := []byte{0x82, 0xd5, 0x10, 0xa7, 0xaa, 0x67, 0x03, 0x65, 0x9f, 0xb9, 0x24, 0x3e, 0x3e, 0x6b, 0x1c, 0xb9, 0xa4, 0xf5, 0x1c, 0x04}

	ans, err := ec.HashAs(algorithm_identifier{Algorithm: idSha1WithRSAEncryption})
	require.Nil(t, err)
	assert.Equal(t, right_ans, ans)
	ans, err = ec.HashAs(algorithm_identifier{Algorithm: idSha1WithRSAEncryption})
	require.Nil(t, err)
	assert.Equal(t, right_ans, ans)
}

func Test_EncapsulatedContentInfo_HashAs_3(t *testing.T) {
	ec := encapsulated_content_info{}
	_, err := ec.HashAs(algorithm_identifier{})
	assert.EqualValues(t, ERR_UNKOWN_ALGORITHM, err.Code())
}

func Test_EncapsulatedContentInfo_SetFallbackFile_1(t *testing.T) {
	ec := encapsulated_content_info{}
	cerr := ec.SetFallbackFile("data/hash_test.txt")
	assert.Nil(t, cerr)
}

func Test_EncapsulatedContentInfo_SetFallbackFile_2(t *testing.T) {
	ec := encapsulated_content_info{}
	cerr := ec.SetFallbackFile("data/non_existent_file.txt")
	require.NotNil(t, cerr)
	assert.EqualValues(t, ERR_FILE_NOT_EXISTS, cerr.Code())
}
