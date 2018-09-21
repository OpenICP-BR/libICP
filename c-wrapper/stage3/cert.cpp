#include <libICP++.h>

using std::string;
using std::vector;
using namespace ICP;

Cert::Cert(icp_cert new_cert_ptr) {
	_cert_ptr = new_cert_ptr;
	update();
}

void Cert::update() {
	icp_kvp *kvps;

	Subject = icp_cert_subject(_cert_ptr);
	SubjectMap.clear();
	kvps = icp_cert_subject_map(_cert_ptr);
	for (int i=0; kvps[i].key != NULL; i++) {
		SubjectMap[kvps[i].key] = kvps[i].val;
	}
	icp_free_kvps(kvps);

	Issuer = icp_cert_issuer(_cert_ptr);
	IssuerMap.clear();
	kvps = icp_cert_issuer_map(_cert_ptr);
	for (int i=0; kvps[i].key != NULL; i++) {
		IssuerMap[kvps[i].key] = kvps[i].val;
	}
	icp_free_kvps(kvps);

	NotBefore = icp_cert_not_before(_cert_ptr);
	NotAfter = icp_cert_not_after(_cert_ptr);

	FingerPrintHuman = icp_cert_fingerprint_human(_cert_ptr);
	FingerPrintAlg = icp_cert_fingerprint_alg(_cert_ptr);
	FingerPrint.clear();
	int n=0;
	uint8_t *buf = icp_cert_fingerprint(_cert_ptr, &n);
	FingerPrint.resize(n);
	for (int i=0; buf != NULL && i < n; i++) {
		FingerPrint.push_back(buf[i]);
	}
}

Cert::~Cert() {
	free(_cert_ptr);
}

bool Cert::IsSelfSigned() {
	return icp_cert_is_self_signed(_cert_ptr);
}

bool Cert::IsCA() {
	return icp_cert_is_ca(_cert_ptr);
}

int LoadCertsFromFile(string path, vector<Cert> &certs, vector<CodedError> &errs) {
	int ans;
	icp_cert *certs_ptr;
	icp_errc *errcs_ptr;

	ans = icp_new_cert_from_file(path.c_str(), &certs_ptr, &errcs_ptr);
	
	certs.clear();
	for (int i=0; certs_ptr[i] != NULL; i++) {
		certs.push_back(Cert(certs_ptr[i]));
	}
	errs.clear();
	for (int i=0; errcs_ptr[i] != NULL; i++) {
		errs.push_back(CodedError(errcs_ptr[i]));
	}

	return ans;
}

int LoadCertsFromBytes(uint8_t *data, int n, vector<Cert> &certs, vector<Error> &errs) {
	icp_cert *certs_ptr;
	icp_errc *errcs_ptr;

	int ans = icp_new_cert_from_bytes(data, n, &certs_ptr, &errcs_ptr);
	
	certs.clear();
	for (int i=0; certs_ptr[i] != NULL; i++) {
		certs.push_back(Cert(certs_ptr[i]));
	}
	errs.clear();
	for (int i=0; errcs_ptr[i] != NULL; i++) {
		errs.push_back(CodedError(errcs_ptr[i]));
	}

	return ans;
}
