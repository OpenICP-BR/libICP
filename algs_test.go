package libICP

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_PairAlgPubKey_RSAPubKey(t *testing.T) {
	p := pair_alg_pub_key{}
	key, err := p.RSAPubKey()
	assert.NotNil(t, err)
	assert.Nil(t, key.N)
	assert.Equal(t, 0, key.E)
}

func Test_parse_rsa_private_key(t *testing.T) {
	t.Error("not written")
}
