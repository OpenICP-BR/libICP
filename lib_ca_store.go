package icp

import (
	"time"
)

type CAStore struct {
	// If true, it will attempt to download missing CAs and CRLs
	AllowDownloads bool
	cas            map[string]Certificate
	inited         bool
}

// This function MUST be called before using this struct. It makes a few maps and adds the following root CAs:
//
// Autoridade Certificadora Raiz Brasileira v1, Autoridade Certificadora Raiz Brasileira v2, Autoridade Certificadora Raiz Brasileira v5
func (store *CAStore) Init() {
	// Do not run this function twice
	if store.inited {
		return
	}
	// Get our root certificates
	certs, err := NewCertificateFromBytes([]byte(root_ca_BR_ICP_V1 + root_ca_BR_ICP_V2 + root_ca_BR_ICP_V5))
	if err != nil {
		panic(err)
	}
	// Save them
	store.cas = make(map[string]Certificate)
	for _, cert := range certs {
		store.cas[cert.SubjectKeyID] = cert
		store.cas[cert.Subject] = cert
	}
	store.inited = true
}

func (store CAStore) VerifyCert(cert Certificate) (bool, []CodedError) {
	return store.verifyCertAt(cert, time.Now())
}

func (store CAStore) verifyCertAt(cert Certificate, now time.Time) (bool, []CodedError) {
	ans_errs := make([]CodedError, 0)
	// Get certification path
	path, err := store.buildPath(cert, _PATH_BUILDING_MAX_DEPTH)
	if err != nil {
		ans_errs = append(ans_errs, err)
		return false, ans_errs
	}

	// Check each certficiate
	for i, cert := range path {
		if !now.After(cert.NotBefore) {
			merr := NewMultiError("certificate not yet valid", ERR_NOT_BEFORE_DATE, nil)
			merr.SetParam("cert.NotBefore", cert.NotBefore)
			merr.SetParam("now", now)
			merr.SetParam("cert.Subject", cert.Subject)
			ans_errs = append(ans_errs, merr)
		}
		if !now.Before(cert.NotAfter) {
			merr := NewMultiError("certificate has expired", ERR_NOT_AFTER_DATE, nil)
			merr.SetParam("cert.NotAfter", cert.NotAfter)
			merr.SetParam("now", now)
			merr.SetParam("cert.Subject", cert.Subject)
			ans_errs = append(ans_errs, merr)
		}
		issuer := Certificate{}
		if i == len(path)-1 {
			issuer = path[len(path)-1]
		} else {
			issuer = path[i+1]
		}
		if ok, err := cert.verifySignedBy(issuer); !ok {
			merr := NewMultiError("certificate has bad signature", ERR_BAD_SIGNATURE, nil, err)
			merr.SetParam("cert.Subject", cert.Subject)
			merr.SetParam("cert.Issuer", cert.Issuer)
			merr.SetParam("issuer.Subject", issuer.Subject)
			ans_errs = append(ans_errs, merr)
		}
	}

	if len(ans_errs) > 0 {
		return false, ans_errs
	}
	return true, nil
}

func (store *CAStore) AddCA(cert Certificate) (bool, []CodedError) {
	return store.addCAatTime(cert, time.Now())
}

func (store *CAStore) addCAatTime(cert Certificate, now time.Time) (bool, []CodedError) {
	return false, nil
}

const _PATH_BUILDING_MAX_DEPTH = 16

func (store CAStore) buildPath(end_cert Certificate, max_depth int) ([]Certificate, CodedError) {
	issuer, ok := store.cas[end_cert.AuthorityKeyID]
	if !ok {
		// Try again
		issuer, ok = store.cas[end_cert.Issuer]
	}
	if !ok {
		merr := NewMultiError("issuer not found", ERR_ISSUER_NOT_FOUND, nil)
		merr.SetParam("AuthorityKeyID", end_cert.AuthorityKeyID)
		return nil, merr
	}
	if max_depth < 0 {
		merr := NewMultiError("reached maximum depth", ERR_MAX_DEPTH_REACHED, nil)
		merr.SetParam("SubjectKeyID", end_cert.SubjectKeyID)
		return nil, merr
	}
	ans := make([]Certificate, 1)
	ans[0] = end_cert
	if end_cert.SelfSigned() {
		// We reached a self signed CA
		return ans, nil
	}
	// RECURSION!
	extra_path, err := store.buildPath(issuer, max_depth-1)
	if extra_path == nil {
		// We failed to build the path
		return nil, NewMultiError("failure on recursion", err.Code(), nil, err)
	}
	// Add the recursion result
	ans = append(ans, extra_path...)
	return ans, nil
}
