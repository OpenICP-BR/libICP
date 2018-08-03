package libICP

import (
	"time"

	rawICP "github.com/gjvnq/libICP/rawICP"
)

type Certificate struct {
	base *rawICP.Certificate
}

func rawICPCert2Cert(cert *rawICP.Certificate) *Certificate {
	new_cert := new(Certificate)
	new_cert.base = cert
	return new_cert
}

func rawICPCertSlice2CertSlice(certs []*rawICP.Certificate) []*Certificate {
	new_certs := make([]*Certificate, len(certs))
	for i := range certs {
		new_certs[i] = rawICPCert2Cert(certs[i])
	}
	return new_certs
}

func (cert Certificate) NotBefore() time.Time {
	return cert.base.NotBefore()
}

func (cert Certificate) NotAfter() time.Time {
	return cert.base.NotAfter()
}

func (cert Certificate) Subject() string {
	return cert.base.Subject()
}

func (cert Certificate) SubjectMap() map[string]string {
	return cert.base.SubjectMap()
}

func (cert Certificate) Issuer() string {
	return cert.base.Issuer()
}

func (cert Certificate) IssuerMap() map[string]string {
	return cert.base.IssuerMap()
}

func (cert Certificate) Serial() string {
	return cert.base.Serial()
}

func (cert Certificate) AuthorityKeyId() string {
	return cert.base.AuthorityKeyId()
}

func (cert Certificate) SubjectKeyId() string {
	return cert.base.SubjectKeyId()
}

func (cert Certificate) BasicConstraints() rawICP.ExtBasicConstraints {
	return cert.base.BasicConstraints()
}

func (cert Certificate) KeyUsage() rawICP.ExtKeyUsage {
	return cert.base.KeyUsage()
}

func (cert Certificate) CRLDistributionPoints() rawICP.ExtCRLDistributionPoints {
	val := cert.base.CRLDistributionPoints()
	ans := rawICP.ExtCRLDistributionPoints{}
	ans.Exists = val.Exists
	ans.URLs = make([]string, len(val.URLs))
	copy(ans.URLs, val.URLs)
	return ans
}

func (cert Certificate) CRLStatus() rawICP.CRLStatus {
	return cert.base.CRLStatus()
}

func (cert Certificate) CRLLastCheck() time.Time {
	return cert.base.CRLLastCheck()
}

// Returns true if the subject is equal to the issuer.
func (cert Certificate) IsSelfSigned() bool {
	return cert.base.IsSelfSigned()
}

// Returns true if this certificate is a certificate authority. This is checked via the following extensions: key usage and basic constraints extension. (see RFC 5280 Section 4.2.1.3 and Section 4.2.1.9, respectively)
func (cert Certificate) IsCA() bool {
	return cert.base.IsCA()
}

func (cert Certificate) CRLLastError() rawICP.CodedError {
	return cert.base.CRLLastError()
}
