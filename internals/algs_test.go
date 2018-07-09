package icp_internals

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_PairAlgPubKey_RSAPubKey(t *testing.T) {
	p := PairAlgPubKey{}
	key, err := p.RSAPubKey()
	assert.NotNil(t, err)
	assert.Nil(t, key.N)
	assert.Equal(t, 0, key.E)
}
