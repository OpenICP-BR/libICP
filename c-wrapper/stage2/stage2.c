#include "libICP.h"
#include "stage1.h"

void safe_free(void *ptr) {
	if (ptr != NULL) {
		free(ptr);
	}
}

char* icp_version() {
	return Version();
}

int icp_errc_code(icp_errc errc) {
	return CodedErrorGetErrorInt(errc);
}

char* icp_errc_code_str(icp_errc errc) {
	return CodedErrorGetErrorStr(errc);
}

char* icp_err_str(icp_err err) {
	return ErrorStr(err);
}

char* icp_cert_subject(icp_cert cert) {
	return CertSubject(cert);
}

char* icp_cert_issuer(icp_cert cert) {
	return CertIssuer(cert);
}

icp_kvp* icp_cert_subject_map(icp_cert cert) {
	return CertSubjectMap(cert);
}

icp_kvp* icp_cert_issuer_map(icp_cert cert) {
	return CertIssuerMap(cert);
}

void icp_free_kvps(icp_kvp *vec) {
	for (int i=0; vec[i].key != NULL || vec[i].val != NULL; i++) {
		icp_free_kvp(vec[i]);
	}
	safe_free(vec);
}

void icp_free_kvp(icp_kvp entry) {
	safe_free(entry.key);
	safe_free(entry.val);
}

int icp_new_cert_from_file(char *path, icp_cert **certs, icp_errc **errcs) {
	return NewCertificateFromFile(path, certs, errcs);
}
