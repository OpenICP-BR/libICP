package icp

import (
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
)

type Certificate struct {
	base certificateT
}

// Example: C=BR/ON=ICP-Brasil/OU=Autoridade Certificadora Raiz Brasileira v2/CN=AC CAIXA v2
// Unkown OIDs will *always* be included at the end. Ex: C=BR/ON=Some Company/2.5.4.17=70160-900
func (cert Certificate) Issuer() string {
	return cert.base.TBSCertificate.Issuer.String()
}

// Example: map[OU:Autoridade Certificadora Raiz Brasileira v2 CN:AC CAIXA v2 C:BR ON:ICP-Brasil]
// Unkown OIDs will *always* be included.
func (cert Certificate) IssuerAsMap() map[string]string {
	return cert.base.TBSCertificate.Issuer.Map()
}

// Example: C=BR/ON=ICP-Brasil/OU=Caixa Economica Federal/CN=AC CAIXA PF v2
// Unkown OIDs will *always* be included at the end. Ex: C=BR/ON=Some Company/2.5.4.17=70160-900
func (cert Certificate) Subject() string {
	return cert.base.TBSCertificate.Subject.String()
}

// Example: map[C:BR ON:ICP-Brasil OU:Caixa Economica Federal CN:AC CAIXA PF v2]
// Unkown OIDs will *always* be included.
func (cert Certificate) SubjectAsMap() map[string]string {
	return cert.base.TBSCertificate.Subject.Map()
}

// Accepts PEM, DER and a mix of both.
func NewCertificateFromFile(path string) ([]Certificate, CodedError) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		merr := NewMultiError("failed to read certificate file", ERR_READ_CERT_FILE, nil, err)
		merr.SetParam("path", path)
		return nil, merr
	}
	certs, errs := NewCertificateFromBytes(dat)
	if errs != nil {
		merr := NewMultiError("failed to parse some certificates", ERR_PARSE_CERT, nil, errs)
		merr.SetParam("path", path)
		return certs, merr
	}
	return certs, nil
}

// Accepts PEM, DER and a mix of both.
func NewCertificateFromBytes(raw []byte) ([]Certificate, []CodedError) {
	var block *pem.Block
	certs := make([]Certificate, 0)
	merrs := make([]CodedError, 0)

	// Try decoding all certificate PEM blocks
	rest := raw
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			new_cert := Certificate{}
			ok, _, merr := new_cert.loadFromDER(block.Bytes)
			if !ok {
				merrs = append(merrs, merr)
			} else {
				certs = append(certs, new_cert)
			}
		}
	}

	// Try decoding the rest as DER certificates
	for {
		var ok bool
		var merr CodedError
		// Finished reading file?
		if rest == nil || len(rest) < 42 {
			break
		}
		new_cert := Certificate{}
		ok, rest, merr = new_cert.loadFromDER(rest)
		if ok {
			certs = append(certs, new_cert)
		} else {
			merrs = append(merrs, merr)
		}
	}

	if len(merrs) == 0 {
		merrs = nil
	}
	return certs, merrs
}

func (cert *Certificate) loadFromDER(data []byte) (bool, []byte, CodedError) {
	rest, err := asn1.Unmarshal(data, &cert.base)
	if err != nil {
		merr := NewMultiError("failed to parse DER certificate", ERR_PARSE_CERT, nil, err)
		merr.SetParam("raw-data", data)
		return false, rest, merr
	}

	return true, rest, nil
}
