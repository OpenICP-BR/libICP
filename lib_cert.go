package icp

import (
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
)

type Certificate struct {
	base           certificateT
	Serial         string
	Issuer         string
	IssuerMap      map[string]string
	Subject        string
	SubjectMap     map[string]string
	SubjectKeyID   string
	AuthorityKeyID string
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

func firstCert(certs []Certificate, stuff []CodedError) Certificate {
	return certs[0]
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

	cert.finishParsing()

	return true, rest, nil
}

func (cert Certificate) SelfSigned() bool {
	// println(cert.SubjectMap["CN"], cert.Subject == cert.Issuer, cert.SubjectKeyID == cert.AuthorityKeyID)
	return cert.Subject == cert.Issuer || cert.SubjectKeyID == cert.AuthorityKeyID
}

func (cert *Certificate) finishParsing() {
	cert.Serial = "0x" + cert.base.TBSCertificate.SerialNumber.Text(16)
	cert.Issuer = cert.base.TBSCertificate.Issuer.String()
	cert.IssuerMap = cert.base.TBSCertificate.Issuer.Map()
	cert.Subject = cert.base.TBSCertificate.Subject.String()
	cert.SubjectMap = cert.base.TBSCertificate.Subject.Map()
	// Just a hack to prevent some problems
	cert.SubjectKeyID = cert.Subject
	cert.AuthorityKeyID = cert.Issuer
	// Look for SubjectKeyID and AuthorityKeyID
	for _, ext := range cert.base.TBSCertificate.Extensions {
		if ext.ExtnID.Equal(idSubjectKeyIdentifier()) {
			cert.SubjectKeyID = nice_hex(ext.ExtnValue)
		}
		if ext.ExtnID.Equal(idAuthorityKeyIdentifier()) {
			cert.AuthorityKeyID = nice_hex(ext.ExtnValue)
		}
	}
}
