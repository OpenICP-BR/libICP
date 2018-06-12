package icp

import "time"

var CAStore CAStoreT

type CAStoreT struct {
	// If true, it will attempt to download missing CAs and CRLs
	AllowDownloads bool
	cas            map[string]Certificate
}

// Adds the root CAs.
func (store *CAStoreT) Init() {
	certs, err := NewCertificateFromBytes([]byte(root_ca_BR_ICP_V1 + root_ca_BR_ICP_V2 + root_ca_BR_ICP_V5))
	if err != nil {
		panic(err)
	}
	store.cas = make(map[string]Certificate)
	for _, cert := range certs {
		store.cas[cert.SubjectKeyID] = cert
	}
}

func (store CAStoreT) VerifyCert(cert Certificate) (bool, []CodedError) {
	return store.verifyCertAt(cert, time.Now())
}

func (store CAStoreT) verifyCertAt(cert Certificate, now time.Time) (bool, []CodedError) {
	return false, nil
}

func (store *CAStoreT) AddCA(cert Certificate) (bool, []CodedError) {
	return store.addCAatTime(cert, time.Now())
}

func (store *CAStoreT) addCAatTime(cert Certificate, now time.Time) (bool, []CodedError) {
	return false, nil
}

const _PATH_BUILDING_MAX_DEPTH = 16

func (store CAStoreT) buildPath(end_cert Certificate, max_depth int) []Certificate {
	issuer, ok := store.cas[end_cert.AuthorityKeyID]
	if !ok || max_depth < 0 {
		// We could not find the issuer or we reached the maximum depth
		return nil
	}
	ans := make([]Certificate, 1)
	ans[0] = end_cert
	if end_cert.AuthorityKeyID == issuer.SubjectKeyID {
		// We reached a self signed CA
		return ans
	}
	// RECURSION!
	extra_path := store.buildPath(issuer, max_depth-1)
	if extra_path == nil {
		// We failed to build the path
		return nil
	}
	// Add the recursion result
	ans = append(ans, extra_path...)
	return ans
}
