package icp_internals

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_PairAlgPubKey_RSAPubKey(t *testing.T) {
	p := PairAlgPubKey{}
	key, err := p.RSAPubKey()
	assert.NotNil(t, err)
	fmt.Println(key)
}
