package icp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_idRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.1", idRSAEncryption().String())
}

func Test_idMd2WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.2", idMd2WithRSAEncryption().String())
}

func Test_idMd4WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.3", idMd4WithRSAEncryption().String())
}

func Test_idMd5WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.4", idMd5WithRSAEncryption().String())
}

func Test_idSha1WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.5", idSha1WithRSAEncryption().String())
}

func Test_idSha256WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.11", idSha256WithRSAEncryption().String())
}

func Test_idSha384WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.12", idSha384WithRSAEncryption().String())
}

func Test_idSha512WithRSAEncryption(t *testing.T) {
	assert.Equal(t, "1.2.840.113549.1.1.13", idSha512WithRSAEncryption().String())
}
