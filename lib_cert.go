package icp

import (
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
)

type Certificate struct {
	base certificateT
}

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
			ok, _, merr := new_cert.LoadFromDER(block.Bytes)
			if !ok {
				merrs = append(merrs, merr)
				println("46: ", merr.Error())
			} else {
				certs = append(certs, new_cert)
			}
		}
	}

	// Try decoding the rest as DER certificates
	for {
		new_cert := Certificate{}
		ok, rest, merr := new_cert.LoadFromDER(rest)
		if ok {
			certs = append(certs, new_cert)
		} else {
			merrs = append(merrs, merr)
			println("61: ", merr.Error())
		}
		// Finished reading file
		if rest == nil || len(rest) == 0 {
			break
		}
	}

	if len(merrs) == 0 {
		merrs = nil
	}
	return certs, merrs
}

func (cert *Certificate) LoadFromDER(data []byte) (bool, []byte, CodedError) {
	rest, err := asn1.Unmarshal(data, &cert.base)
	if err != nil {
		merr := NewMultiError("failed to parse DER certificate", ERR_PARSE_CERT, nil, err)
		merr.SetParam("raw-data", data)
		return false, rest, merr
	}

	return true, rest, nil
}
