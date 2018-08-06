package libICP

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewCertificateFromFile_1(t *testing.T) {
	// Write file
	tmp_file, err := ioutil.TempFile("", "")
	assert.Nil(t, err)
	_, err = tmp_file.WriteString(test_1_pem)
	assert.Nil(t, err)

	// Test code
	certs, errs := NewCertificateFromFile(tmp_file.Name())
	assert.Nil(t, errs)
	cert := certs[0]

	assert.Equal(t, "0x28eea57c362904d8", cert.Serial)
	assert.Equal(t, "C=BR/O=ICP-Brasil/OU=Autoridade Certificadora Raiz Brasileira v2/CN=AC CAIXA v2", cert.Issuer)
	assert.Equal(t, "C=BR/O=ICP-Brasil/OU=Caixa Economica Federal/CN=AC CAIXA PF v2", cert.Subject)
	assert.Equal(t, "9E:2A:D6:41:57:00:AF:5B:ED:07:F8:D0:5C:8E:F3:6D:E6:E5:0C:1A", cert.SubjectKeyId)
	assert.Equal(t, "0F:50:24:31:E4:BA:BC:B1:99:49:26:35:ED:0E:D0:75:FE:9C:9F:55", cert.AuthorityKeyId)
	assert.True(t, cert.ext_key_usage.Exists)
	assert.False(t, cert.ext_key_usage.DigitalSignature)
	assert.False(t, cert.ext_key_usage.NonRepudiation)
	assert.False(t, cert.ext_key_usage.KeyEncipherment)
	assert.False(t, cert.ext_key_usage.DataEncipherment)
	assert.False(t, cert.ext_key_usage.KeyAgreement)
	assert.True(t, cert.ext_key_usage.KeyCertSign)
	assert.True(t, cert.ext_key_usage.CRLSign)
	assert.True(t, cert.ext_basic_constraints.Exists)

	// Finish
	os.Remove(tmp_file.Name())
}

func Test_CheckAgainstIssuerCRL_1(t *testing.T) {
	// Get cert
	certs, errs := NewCertificateFromFile("data/test-chain/intermediate/fakebank/certs/fakebank-ca.crt.pem")
	require.Nil(t, errs)
	require.Equal(t, 1, len(certs))
	ca := certs[0]

	// Get cert
	certs, errs = NewCertificateFromFile("data/test-chain/intermediate/fakebank/certs/fulano.crt.pem")
	require.Equal(t, 1, len(certs))
	fulano := certs[0]

	// Get CRL
	crls, errs := new_CRL_from_file("data/test-chain/intermediate/fakebank/crl/fakebank-1.crl.pem")
	require.Nil(t, errs)
	require.Equal(t, 1, len(crls))

	// Try to parse
	err := ca.process_CRL(crls[0])
	require.Nil(t, err)
	assert.Nil(t, ca.CRLLastError())

	// Check
	fulano.CheckAgainstIssuerCRL(&ca)
	assert.EqualValues(t, CRL_NOT_REVOKED, fulano.CRL_Status)
	assert.Equal(t, ca.crl.TBSCertList.ThisUpdate, fulano.CRL_LastCheck)
}

func Test_CheckAgainstIssuerCRL_2(t *testing.T) {
	// Get cert
	certs, errs := NewCertificateFromFile("data/test-chain/intermediate/fakebank/certs/fakebank-ca.crt.pem")
	require.Nil(t, errs)
	require.Equal(t, 1, len(certs))
	ca := certs[0]

	// Get cert
	certs, errs = NewCertificateFromFile("data/test-chain/intermediate/fakebank/certs/fulano.crt.pem")
	require.Equal(t, 1, len(certs))
	fulano := certs[0]

	// Get CRL
	crls, errs := new_CRL_from_file("data/test-chain/intermediate/fakebank/crl/fakebank-2.crl.pem")
	require.Nil(t, errs)
	require.Equal(t, 1, len(crls))

	// Try to parse
	err := ca.process_CRL(crls[0])
	require.Nil(t, err)
	assert.Nil(t, ca.CRLLastError())

	// Check
	fulano.CheckAgainstIssuerCRL(&ca)
	assert.EqualValues(t, CRL_REVOKED, fulano.CRL_Status)
	assert.Equal(t, ca.crl.TBSCertList.ThisUpdate, fulano.CRL_LastCheck)
}

const test_1_pem = "-----BEGIN CERTIFICATE-----\nMIIHMDCCBRigAwIBAgIIKO6lfDYpBNgwDQYJKoZIhvcNAQENBQAwbjELMAkGA1UE\nBhMCQlIxEzARBgNVBAoTCklDUC1CcmFzaWwxNDAyBgNVBAsTK0F1dG9yaWRhZGUg\nQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjIxFDASBgNVBAMTC0FDIENB\nSVhBIHYyMB4XDTExMTIyMzEzNTI1OFoXDTE5MTIyMTEzNTI1OFowXTELMAkGA1UE\nBhMCQlIxEzARBgNVBAoMCklDUC1CcmFzaWwxIDAeBgNVBAsMF0NhaXhhIEVjb25v\nbWljYSBGZWRlcmFsMRcwFQYDVQQDDA5BQyBDQUlYQSBQRiB2MjCCAiIwDQYJKoZI\nhvcNAQEBBQADggIPADCCAgoCggIBANWvsvNnqWNg+rR82rG/WpAs6NKhKpgXcfRg\n1G8onArhQ9MSaLnGYTMgkWsbCfOrrCAtE5TVUDJG60+swtwAsIPkZLl7LwhQ6AAQ\nTX9qknKMPV7sAZlW3SJO+f5uurT894QpqzBW22zT6dgSlhED5HHVqRbsUHoYDH/d\nnTQCvxkHyDELwowjHffg8/80VOE9kUAjDAWLY4ZTvW+2KRJXFzYyDScA89f5aM1R\nlLUhAW2hq/KmnunfMsCVUNqQ2LVwNCFjlfn0MHdiE/OooIsL/fE9gUuddCw1h+g1\nIcgji4dqCPCoju4/XlDeTF9Z29qCrLuuSKlIdTdUU2aPzLGkzz04/UavAapgOWIe\n+5DirtLcBST4lTv9TcXleFNtygBCFFNbEcpa2iqYqdw9EndC3k7qYaeijgZgrRBH\n4R89k0jbMZG0bKIttCIizOCcHzJJhGx+nQNuoVvPeLyBcIxSX9rvNTzzIIuyH2jV\nlhrqgAJnDsasTW34FJTB9BVqMnM1k4+IO2ac+zKgfrgTO3lzyqJcTyN2UCbqVw2r\nSnLxB7ZZTuu3rn8joXQAQ3ABk6phTnzZ08RfHK4Zi+dxdFWxwCZjfRn7KSvgYLMj\nMmNKqbvWtr41FN2zaO5oc46CKKMIgFShJkWL7fvaUHmxc9x80YZsOamraU5gviXR\nnehfyN3bAgMBAAGjggHhMIIB3TAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE\nAwIBBjAdBgNVHQ4EFgQUnirWQVcAr1vtB/jQXI7zbeblDBowHwYDVR0jBBgwFoAU\nD1AkMeS6vLGZSSY17Q7Qdf6cn1UwgcUGA1UdIASBvTCBujBbBgZgTAECAQgwUTBP\nBggrBgEFBQcCARZDaHR0cDovL2NlcnRpZmljYWRvZGlnaXRhbC5jYWl4YS5nb3Yu\nYnIvZG9jdW1lbnRvcy9kcGNhYy1jYWl4YXBmLnBkZjBbBgZgTAECAwgwUTBPBggr\nBgEFBQcCARZDaHR0cDovL2NlcnRpZmljYWRvZGlnaXRhbC5jYWl4YS5nb3YuYnIv\nZG9jdW1lbnRvcy9kcGNhYy1jYWl4YXBmLnBkZjCBsQYDVR0fBIGpMIGmMCugKaAn\nhiVodHRwOi8vbGNyLmNhaXhhLmdvdi5ici9hY2NhaXhhdjIuY3JsMCygKqAohiZo\ndHRwOi8vbGNyMi5jYWl4YS5nb3YuYnIvYWNjYWl4YXYyLmNybDBJoEegRYZDaHR0\ncDovL3JlcG9zaXRvcmlvLmljcGJyYXNpbC5nb3YuYnIvbGNyL0NBSVhBL0FDQ0FJ\nWEEvYWNjYWl4YXYyLmNybDANBgkqhkiG9w0BAQ0FAAOCAgEAg5dz7NCYlQi1O/WI\nOHr2VPWEaJXLP6ciVVW21uHaop78VndwOT9NbhTANLC92maSTCK3QeJaLtL5lAjL\nUo3mA0y976nkaXlQW2jFR3eMIr7vU7xSX/eL5144e6IUbY+YS74EwH8Wn/jP2AOR\n5r89CTNQ+CqMy8LHFab7tHcwCmUnalbTt7t6zANN8kJG87nrNu3tLhhT2kaGe2O7\nUUV3Xi17NoUV92i8T0u0eQ8Nsv4yqtsgSUCebjnlgTaJskIUow0UMgRzZWRaO99L\nF4U8BhvPF82UZWmDzMm+Ktswwy+nWGEmSzTOlaLv9UYzun1kDMC6pqWziyLjmz7v\neM9eaTKwUBTrqAe/5U8FYSufeh4j9p8KGKLkwTjwAkbQjjRi/vKXZFqw0v1AxoC4\n9NZ0tvOuJPcprXMc6idhjgvaz1Ye0uXpMyT4bp5f1/ufkMProiLUo/z8YtPZ/wzp\nyvVtle+4Ri3Z7qWRAwNZ2Nd70jtKjfG1GIi3blTdMWL1gr6+tMLB6OnyZTh8X2aD\nCtdQy/S55JjD+t2MxtW22IaS+KOWF2IGWZm4L0b/rGwvk0ZN0djJEyrac7Y41zyM\nlzJjPlsetJXV+eXPBkkk/RqJnoHB+QOGzK1+ssJ4cq+0SRH6H6MuQLdkPcXRx1g1\nax6m9jdWLtwKLLp3+SXt01ZZVBM=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIEgDCCA2igAwIBAgIBATANBgkqhkiG9w0BAQUFADCBlzELMAkGA1UEBhMCQlIx\nEzARBgNVBAoTCklDUC1CcmFzaWwxPTA7BgNVBAsTNEluc3RpdHV0byBOYWNpb25h\nbCBkZSBUZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNDAyBgNVBAMTK0F1\ndG9yaWRhZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjEwHhcNMDgw\nNzI5MTkxNzEwWhcNMjEwNzI5MTkxNzEwWjCBlzELMAkGA1UEBhMCQlIxEzARBgNV\nBAoTCklDUC1CcmFzaWwxPTA7BgNVBAsTNEluc3RpdHV0byBOYWNpb25hbCBkZSBU\nZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNDAyBgNVBAMTK0F1dG9yaWRh\nZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjEwggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQDOHOi+kzTOybHkVO4J9uykCIWgP8aKxnAwp4CM\n7T4BVAeMGSM7n7vHtIsgseL3QRYtXodmurAH3W/RPzzayFkznRWwn5LIVlRYijon\nojQem3i1t83lm+nALhKecHgH+o7yTMD45XJ8HqmpYANXJkfbg3bDzsgSu9H/766z\nYn2aoOS8bn0BLjRg3IfgX38FcFwwFSzCdaM/UANmI2Ys53R3eNtmF9/5Hw2CaI91\nh/fpMXpTT89YYrtAojTPwHCEUJcV2iBL6ftMQq0raI6j2a0FYv4IdMTowcyFE86t\nKDBQ3d7AgcFJsF4uJjjpYwQzd7WAds0qf/I8rF2TQjn0onNFAgMBAAGjgdQwgdEw\nTgYDVR0gBEcwRTBDBgVgTAEBADA6MDgGCCsGAQUFBwIBFixodHRwOi8vYWNyYWl6\nLmljcGJyYXNpbC5nb3YuYnIvRFBDYWNyYWl6LnBkZjA/BgNVHR8EODA2MDSgMqAw\nhi5odHRwOi8vYWNyYWl6LmljcGJyYXNpbC5nb3YuYnIvTENSYWNyYWl6djEuY3Js\nMB0GA1UdDgQWBBRCsixcdAEHvpv/VTM77im7XZG/BjAPBgNVHRMBAf8EBTADAQH/\nMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQUFAAOCAQEAWWyKdukZcVeD/qf0\neg+egdDPBxwMI+kkDVHLM+gqCcN6/w6jgIZgwXCX4MAKVd2kZUyPp0ewV7fzq8TD\nGeOY7A2wG1GRydkJ1ulqs+cMsLKSh/uOTRXsEhQZeAxi6hQ5GArFVdtThdx7KPoV\ncaPKdCWCD2cnNNeuUhMC+8XvmoAlpVKeOQ7tOvR4B1/VKHoKSvXQw2f3jFgXbwoA\noyYQtGAiOkpIpdrgqYTeQ9ufQ6c/KARHki/352R1IdJPgc6qPmQO4w6tVZp+lJs0\nwdCuaU4eo9mzh1facMJafYfN+b833u1WNfe3Ig5Pkrg/CN+cnphe8m+5+pss+M1F\n2HKyIA==\n-----END CERTIFICATE-----"

const crl_raiz_v2 = "MIIDUTCCATkCAQEwDQYJKoZIhvcNAQENBQAwgZcxCzAJBgNVBAYTAkJSMRMwEQYDVQQKEwpJQ1At\nQnJhc2lsMT0wOwYDVQQLEzRJbnN0aXR1dG8gTmFjaW9uYWwgZGUgVGVjbm9sb2dpYSBkYSBJbmZv\ncm1hY2FvIC0gSVRJMTQwMgYDVQQDEytBdXRvcmlkYWRlIENlcnRpZmljYWRvcmEgUmFpeiBCcmFz\naWxlaXJhIHYyFw0xODA1MDQxMzM0NTFaFw0xODA4MDIxMzM0NTFaMDwwEgIBAhcNMTEwOTIwMTg0\nMjEyWjASAgEDFw0xMTA3MDExMjU4MTlaMBICAQQXDTExMDkyMDE4NDAzMVqgLzAtMB8GA1UdIwQY\nMBaAFAw5IDq3AR/L1yh9QaDH+kqtMiS+MAoGA1UdFAQDAgEoMA0GCSqGSIb3DQEBDQUAA4ICAQAY\nrcbmUwnumf2dn0Pq5cPJDducXWh//bYCQS3Si7/AgMQiVoqK5FWN7sK2Sy5tKp1ccMQ0hAoiiONS\npgAHzVqe28l1k2grJA2Z37F0TwkRIYtkDAHaa42sf2mF+zMeiifYIKpk8tHC7aYCZHhdbUIQFLQi\nupAN2c7oRR6SOz+k9vBhqLd1eFI7R5ow2Uv3Zd/NLQyGqOr5prXZWEIGEpCjBSPcToeQ7srQ2wLM\nC9QoNEtFw6P1ZrwkIx21PfyTd0Clve+Y50TFta8ChHcRYRaSga7W/AziFtuXocSd5PhSFr/ceDPd\ng0FJgC5GfVTLwAGMg9P5ScycEtzbBtdsNjRnj1VV6muBeDgrdyQ4DzneJjJJG+tRnyV/YyEgE3fU\n3b8ADae5mpH0lGgrh05104CYmZiLlN7ZqfvaJT3Kr3Nw9FY+YB/6aEW2bbV7epvMrmpbBcJW+ZET\nfrnKwem6MVHxQ6tXAWGFxYNawCXTyAr7Vgl3xtaD6UPBRL1z5hzRmGk1WZa3ZS8fyGsrHvogHCxz\nvwvkXXslJz7SnKzcmnaqsFyIvTASS9zA0uvYsM7WvPjSDwHBJsnFeL/p5daTvRjA42xhTN8kInUc\nUVzX4PSdWZH7/REuDDsk+vxAdj1Pa+zmpiwSVGLpU09orYfl43HSjymFJKwq6r54ScH6M56QQQ=="
