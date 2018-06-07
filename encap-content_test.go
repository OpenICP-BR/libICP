package icp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_EncapsulatedContentInfoT_AdjustForNoSigners(t *testing.T) {
	ec := EncapsulatedContentInfoT{}
	ec.AdjustForNoSigners()

	assert.Equal(t, IdData(), ec.EContentType, "see RFC 5652 Section 5.2 Page 11 Paragraph 2")
	assert.Nil(t, ec.EContent, "see RFC 5652 Section 5.2 Page 11 Paragraph 2")
}
