package icp

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_CAStore_buildPath_1(t *testing.T) {
	store := CAStore{}
	store.Init()
	end_cert := firstCert(NewCertificateFromBytes([]byte(root_ca_BR_ICP_V1)))
	ans, err := store.buildPath(end_cert, _PATH_BUILDING_MAX_DEPTH)
	assert.Nil(t, err)
	right_ans := make([]Certificate, 1)
	right_ans[0] = end_cert
	assert.Equal(t, right_ans, ans)
}

func Test_CAStore_buildPath_2(t *testing.T) {
	store := CAStore{}
	store.Init()
	certs, err := NewCertificateFromBytes([]byte(pem_ac_soluti + root_ca_BR_ICP_V2))
	assert.Nil(t, err)
	end_cert := certs[0]
	root := certs[1]
	ans, errs := store.buildPath(end_cert, _PATH_BUILDING_MAX_DEPTH)
	assert.Nil(t, errs)
	right_ans := make([]Certificate, 2)
	right_ans[0] = end_cert
	right_ans[1] = root
	assert.NotNil(t, ans)
	assert.Equal(t, right_ans, ans)
}

func Test_CAStore_buildPath_3(t *testing.T) {
	store := CAStore{}
	store.Init()
	certs, err := NewCertificateFromBytes([]byte(pem_ac_digital + pem_ac_soluti + root_ca_BR_ICP_V2))
	assert.Nil(t, err)
	end_cert := certs[0]
	middle_ca := certs[1]
	root := certs[2]
	store.cas[middle_ca.SubjectKeyID] = middle_ca
	store.cas[middle_ca.Subject] = middle_ca
	ans, errs := store.buildPath(end_cert, _PATH_BUILDING_MAX_DEPTH)
	assert.Nil(t, errs)
	right_ans := make([]Certificate, 3)
	right_ans[0] = end_cert
	right_ans[1] = middle_ca
	right_ans[2] = root
	assert.NotNil(t, ans)
	assert.Equal(t, right_ans, ans)
}

func Test_CAStore_verifyCertAt_1(t *testing.T) {
	store := CAStore{}
	store.Init()
	certs, err := NewCertificateFromBytes([]byte(pem_ac_soluti + root_ca_BR_ICP_V2))
	assert.Nil(t, err)
	end_cert := certs[0]
	root := certs[1]

	some_time := time.Unix(1528997864, 0)
	errs := store.verifyCertAt(root, some_time)
	assert.Nil(t, errs)

	errs = store.verifyCertAt(end_cert, some_time)
	assert.Nil(t, errs)
}

func Test_CAStore_verifyCertAt_2(t *testing.T) {
	store := CAStore{}
	store.Init()
	certs, err := NewCertificateFromBytes([]byte(pem_ac_soluti + root_ca_BR_ICP_V2))
	assert.Nil(t, err)
	end_cert := certs[0]
	root := certs[1]

	some_time := time.Unix(0, 0)
	errs := store.verifyCertAt(root, some_time)
	assert.NotNil(t, errs)
	assert.Equal(t, 1, len(errs), "there should be only one error")
	assert.Equal(t, ERR_NOT_BEFORE_DATE, errs[0].Code())

	errs = store.verifyCertAt(end_cert, some_time)
	assert.NotNil(t, errs)
	assert.Equal(t, 2, len(errs), "there should be only two error")
	assert.Equal(t, ERR_NOT_BEFORE_DATE, errs[0].Code())
	assert.Equal(t, ERR_NOT_BEFORE_DATE, errs[1].Code())
}

func Test_CAStore_verifyCertAt_3(t *testing.T) {
	store := CAStore{}
	store.Init()
	certs, err := NewCertificateFromBytes([]byte(pem_ac_digital))
	assert.Nil(t, err)
	end_cert := certs[0]

	some_time := time.Unix(0, 0)
	errs := store.verifyCertAt(end_cert, some_time)
	assert.NotNil(t, errs)
	assert.Equal(t, 1, len(errs), "there should be only one error")
	assert.Equal(t, ERR_ISSUER_NOT_FOUND, errs[0].Code())
}

func Test_CAStore_addCAatTime(t *testing.T) {
	store := CAStore{}
	store.Init()
	certs, err := NewCertificateFromBytes([]byte(pem_ac_digital + pem_ac_soluti))
	assert.Nil(t, err)
	end_ca := certs[0]
	middle_ca := certs[1]
	some_time := time.Unix(1528997864, 0)

	errs := store.addCAatTime(end_ca, some_time)
	assert.Equal(t, len(errs), 1)
	assert.Equal(t, errs[0].Code(), ERR_ISSUER_NOT_FOUND)

	errs = store.addCAatTime(middle_ca, some_time)
	assert.Nil(t, errs)

	errs = store.addCAatTime(end_ca, some_time)
	assert.Nil(t, errs)
}

func Test_CAStore_parse_cas_zip(t *testing.T) {
	store := CAStore{}
	store.Init()
	raw, err := ioutil.ReadFile("data/ACcompactado.zip")
	assert.Nil(t, err)

	err = store.parse_cas_zip(raw, int64(len(raw)))
	assert.Nil(t, err)
}

const pem_ac_soluti = "-----BEGIN CERTIFICATE-----\nMIIGOzCCBCOgAwIBAgIBEDANBgkqhkiG9w0BAQ0FADCBlzELMAkGA1UEBhMCQlIx\nEzARBgNVBAoTCklDUC1CcmFzaWwxPTA7BgNVBAsTNEluc3RpdHV0byBOYWNpb25h\nbCBkZSBUZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNDAyBgNVBAMTK0F1\ndG9yaWRhZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjIwHhcNMTIx\nMjAzMTIzOTEzWhcNMjMwNjIwMjM1OTU5WjBsMQswCQYDVQQGEwJCUjETMBEGA1UE\nChMKSUNQLUJyYXNpbDE0MDIGA1UECxMrQXV0b3JpZGFkZSBDZXJ0aWZpY2Fkb3Jh\nIFJhaXogQnJhc2lsZWlyYSB2MjESMBAGA1UEAxMJQUMgU09MVVRJMIICIjANBgkq\nhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAm+fP9BaY+XTsxfG1QkZbm4h8Ru6dZURx\nX+t+BBSni9YG0ojBKIKiY/mGTLfBfKydZ+lfVmT51uocPmtCbs4pUIDhtCZ1NP+8\n2sEpYry3wMLd5DvCVpuIQa08Y2RsrPIKCxZCgNV2GCw6aFL753LysYatGEOZ09pQ\nQDDiK9Lp2ETXwgwQsc4abMQhhe3M/jysUJwIKy7CAg0uBGdIsPl9WVbEhmK+S/Or\ny+lE/zAKtalVxatjUCQrBBu83kN6k0WM4mG5usoCeSHejX+F+PAwJcoAOBBFRNqw\nN2m95v3t0eL6MhNrxpM/wZGT574ARKIoKBuvemWnuA2GI8zCfTSFxkuc2oMJeqt9\nWR4ommK1VyxMHSQD+BKF+ae21mWpK5CePc4rj+O1zUwu3GJxJ4taXCs1e8kDuO39\nVOeJ7i3KxiF2PmckN1QdkHZBbVmEks9+lzD9kdtaj/5r2hu04ong7+DsoG0N55ut\n3gj/DQccxarvOCgkgox+Bse5fsk/2IVW7fNBav3TfGyQaNYRfl5zl8ReVnL7ibVS\n5qUFxeImeXBj8ofPFF98O2PN89Y9r3xngXkjaUlqFsTPFGvrYTRAv6KVOZYitIWi\nbAdNzpooXWmccMik+Rxgqn0M22IAxHAFUceFNg5E5yA0HRbOcI7oKdb/wSTMLoTj\nFXQAgLj+gU8CAwEAAaOBuzCBuDAUBgNVHSAEDTALMAkGBWBMAQEuMAAwPwYDVR0f\nBDgwNjA0oDKgMIYuaHR0cDovL2FjcmFpei5pY3BicmFzaWwuZ292LmJyL0xDUmFj\ncmFpenYyLmNybDAfBgNVHSMEGDAWgBQMOSA6twEfy9cofUGgx/pKrTIkvjAdBgNV\nHQ4EFgQUZKWFK33P30DFzaIqls7qQw/rlGowDwYDVR0TAQH/BAUwAwEB/zAOBgNV\nHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQENBQADggIBAGPZajNPNzW7Ir5TW3MTYvJ+\nJNngfHF7rbJKPjPo+Rb7A4rzorl0H1a0geBCGqN+FCCh0ltp9H641wcHfwSRYmF+\ng0JKUOd58FUxh1YYEkc5SyqI+Y0BRiM28vit07fHFqCTArrgaMwjcQ41N0ePSrCZ\nwZKD3aA+8m0a9NcKSusV3CjmhcQ+Kwnnk4tGYq5R4WullaumCn7k9PCySenMte8P\nZgvBOZGI6IHxPKOk9b3IrC+A7JYuuIQ1CueRuycdwOqyuN3X0IyU+N3TGXFOSu0u\nsQJj0W8Rj11RSIG3/aGVqjUVWQJiiaOJW4JGVF4GXFBRa4E/1Ieh4qhyFqDv5i5q\n+e5Cb20lA/RyhqWeTZ024At2/XIKj3N7SnDScL1n2z4ND9OAAPthIuMCzzGe9RyP\n78QTBCX+sATZ5LtlIiWP8hdt2frpargnt7f0wHfMiSCs1fOqLCUd6py6XWahEknF\n3daqSvxpT9RnYISZrNxNvtGKbghqPSfGOypH09h+JorKbb8dgCWjMfiJzw/XMpUe\nIPVT6HkQHDzMGI2CRYGGxr+cXmjiHF74+R2nZa7rD/ConBR02nucX/ry67g+LY+P\nHfTc19kWMeRI77RwA0w7rNw6UQUhPb6OyYI/1AAGR0tGgt/0crXRufz8n5P3U10d\nlZNUzDUzly3ClcwIGaJW\n-----END CERTIFICATE-----\n"

const pem_ac_digital = "-----BEGIN CERTIFICATE-----\nMIIIJTCCBg2gAwIBAgIBAjANBgkqhkiG9w0BAQ0FADBsMQswCQYDVQQGEwJCUjET\nMBEGA1UEChMKSUNQLUJyYXNpbDE0MDIGA1UECxMrQXV0b3JpZGFkZSBDZXJ0aWZp\nY2Fkb3JhIFJhaXogQnJhc2lsZWlyYSB2MjESMBAGA1UEAxMJQUMgU09MVVRJMB4X\nDTE1MDIyNjE4MTE1MloXDTIzMDYyMDIzNTg1OVowgYExCzAJBgNVBAYTAkJSMRMw\nEQYDVQQKEwpJQ1AtQnJhc2lsMTQwMgYDVQQLEytBdXRvcmlkYWRlIENlcnRpZmlj\nYWRvcmEgUmFpeiBCcmFzaWxlaXJhIHYyMRIwEAYDVQQLEwlBQyBTT0xVVEkxEzAR\nBgNVBAMTCkFDIERJR0lUQUwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC\nAQC8VHcpUXNZcpnolH13gkA04xKY/DvWkQUxmLp/01pr/rJGv5pDMMZUXEL30Jf1\nNUlfrsWvHfumKDZI7wZoGqNDwJGOFiPnFaY04j0chgJQqKBoYdd9Dp8QlWHsbdit\nRKQK8dRPWmCZLj560a3Xx+8XDIeja772JAuL2HUdR4huL6uClo5WzVUBfonXnLe3\nFfoubz89UURtR6zEJd9h+v1BG+YN5U4n2hVK4dzIM6sVW94p/A25UIioGdhiNS+R\nIuCIz2096zpxl1w9NreQFvU05dmXpLadXT9FUVC90BcMT50BjgyFdkzfX046RqIg\nu2h76H2ejLpVGLqwx3vtjIA3B2obzSdY6tdj9yAjsAEm+xIB8PIM4S/10Xkz5Erw\ns3qaWuOr0KU+2BZ5o2Cn+vQnksVbnXj6jlZgI6Aidx+VuORvlt9L7VYao/ZzYpT9\nWHgzpnyocWQ17IHxXeCG04J6UZyQwrvBVVs6bUQVTajCmJG0Kn9444/bpp4EgL9w\nMsfY7xieQR6ojQglApEKn/s6+Pr8J4wFmZzZ0T1YxOSigsEE296EW1bysgSkAZZp\nxLqSXvsAjatUFTJvKS1O5dWYloL1MvKgChRvUtFcn13eynY01zW/iTPS/BZ7KL/r\n2evvDww5KVY7XHGx1N0Hnqeg+Pkl8brKSpjSHe0rzP57mwIDAQABo4ICujCCArYw\nHQYDVR0OBBYEFIlRB5jQucaI+CKSFxwuBNOFKjZeMA8GA1UdEwEB/wQFMAMBAf8w\nHwYDVR0jBBgwFoAUZKWFK33P30DFzaIqls7qQw/rlGowggGLBgNVHSAEggGCMIIB\nfjBKBgZgTAECATYwQDA+BggrBgEFBQcCARYyaHR0cHM6Ly9jY2QuYWNzb2x1dGku\nY29tLmJyL2RvY3MvZHBjLWFjLXNvbHV0aS5wZGYwSwYHYEwBAoIvCjBAMD4GCCsG\nAQUFBwIBFjJodHRwczovL2NjZC5hY3NvbHV0aS5jb20uYnIvZG9jcy9kcGMtYWMt\nc29sdXRpLnBkZjBLBgdgTAECgjAIMEAwPgYIKwYBBQUHAgEWMmh0dHBzOi8vY2Nk\nLmFjc29sdXRpLmNvbS5ici9kb2NzL2RwYy1hYy1zb2x1dGkucGRmMEoGBmBMAQID\nMzBAMD4GCCsGAQUFBwIBFjJodHRwczovL2NjZC5hY3NvbHV0aS5jb20uYnIvZG9j\ncy9kcGMtYWMtc29sdXRpLnBkZjBKBgZgTAECBBkwQDA+BggrBgEFBQcCARYyaHR0\ncHM6Ly9jY2QuYWNzb2x1dGkuY29tLmJyL2RvY3MvZHBjLWFjLXNvbHV0aS5wZGYw\ngcMGA1UdHwSBuzCBuDA1oDOgMYYvaHR0cDovL2NjZC5hY3NvbHV0aS5jb20uYnIv\nbGNyL2FjLXNvbHV0aS12MS5jcmwwNqA0oDKGMGh0dHA6Ly9jY2QyLmFjc29sdXRp\nLmNvbS5ici9sY3IvYWMtc29sdXRpLXYxLmNybDBHoEWgQ4ZBaHR0cDovL3JlcG9z\naXRvcmlvLmljcGJyYXNpbC5nb3YuYnIvbGNyL0FDU09MVVRJL2FjLXNvbHV0aS12\nMS5jcmwwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBDQUAA4ICAQAFejHGn4Mk\ntlGfqUJtevhwTKZUxjRj56Q1ZXb2AjvVKfT9oXhUDNf5Ba8YBywcuhOtAxFUZZ9O\ny+EjYzXBmdwWJ9KIw6lnWgL4UdTLbeqSckHfkIRe98OWbxbQ5qy0tkwhicJoHqsg\nOib22KURcQODcwCdAndTN+swPVRW7NiPbg7VdqiSkYrRXpHyI/Pj7yjM6k+CEI7Y\nWUzhH0lc7ah/3u4SWiRaT/899r3AqSp08ECDFjGfKUJThgBpIF8lWgk2mOebEHcD\nv9NYDcZDxdqk17Ihmid3cFcxInw/J1rkt33rwm/pJP9N08xfn6bHxXyT4/d3Nr3c\ndEpkepSjBlz1i7VGGRdUnbLaxSApN9BC2NEQvZ8kF4/jur2Ll3x3Q7ycmJ8a7HwW\nhXlDPpmNdnXa4amWpdskir9CfNfXoP0l4MxZuzfq7sPMqgzyOlQrbIUwvWgl1ziG\nSzBa9bhlBVc/J/op9+dO2MsYsJUmrOudCFoDQS17gVVB089mFWTr56ft6SP5tR3b\n5kDB8oKW0PKSWKgtGl6/L7pmgMHk2NfRjTVJr82EFeAR6KzIPsm4AUiMNAHIZsls\nwKPki85/miQNmMpAXTkiPnXmZTUT33BGquDmzGJedQmzzUYt9eQpZPe9ir+2NCa0\nXRACJPF1MHOLTIEPsjVjvgYn10KXoziUtQ==\n-----END CERTIFICATE-----\n"
