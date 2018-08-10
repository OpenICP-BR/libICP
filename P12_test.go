package libICP

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewRootCA(t *testing.T) {
	p12, cerr := NewRootCA(time.Unix(1514764800, 0), time.Unix(1546214400, 0))
	require.Nil(t, cerr)
	assert.Equal(t, TESTING_ROOT_CA_SUBJECT, p12.Cert.Subject)
	assert.Equal(t, TESTING_ROOT_CA_SUBJECT, p12.Cert.Issuer)
	cerr = p12.SaveCertToFile("my_cert.der")
	assert.Nil(t, cerr)
	os.Remove("my_cert.der")
}
