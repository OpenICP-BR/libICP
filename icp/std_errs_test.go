package icp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ErrorCode_String(t *testing.T) {
	var err ErrorCode

	err = -1
	assert.Equal(t, "ERR_-1", err.String())
	err = ERR_OK
	assert.Equal(t, "ERR_OK", err.String())
}

func Test_CRLStatus_String(t *testing.T) {
	var err CRLStatus

	err = -1
	assert.Equal(t, "CRL_-1", err.String())
	err = CRL_NOT_REVOKED
	assert.Equal(t, "CRL_NOT_REVOKED", err.String())
}
