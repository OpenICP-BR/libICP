package icp

import "io/ioutil"

type Certificate struct {
}

func (cert *Certificate) LoadFromFile(path string) (bool, CodedError) {
	dat, err := ioutil.ReadFile("/tmp/dat")
	if err != nil {
		return false, NewMultiError("failed to read certificate file", ERR_READ_CERT_FILE, nil, nil, err)
	}
	return cert.LoadFromBytes(dat)
}

func (cert *Certificate) LoadFromBytes(raw []byte) (bool, CodedError) {
	return false, nil
}
