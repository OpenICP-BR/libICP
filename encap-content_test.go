package icp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_encapsulatedContentInfoT_AdjustForNoSigners(t *testing.T) {
	ec := encapsulatedContentInfoT{}
	ec.AdjustForNoSigners()

	assert.Equal(t, idData(), ec.EContentType, "see RFC 5652 Section 5.2 Page 11 Paragraph 2")
	assert.Nil(t, ec.EContent, "see RFC 5652 Section 5.2 Page 11 Paragraph 2")
}
