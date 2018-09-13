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

name_entry* icp_cert_subject_map(icp_cert cert) {
	// Make buffers
	int buf_size = 64;
	name_entry *entries = calloc(buf_size+1, sizeof(name_entry));

	// Call go
	CertSubjectMap(cert, entries);

	// End
	return entries;
}

name_entry* icp_cert_issuer_map(icp_cert cert) {
	// Make buffers
	int buf_size = 64;
	name_entry *entries = calloc(buf_size+1, sizeof(name_entry));

	// Call go
	CertIssuerMap(cert, entries);

	// End
	return entries;
}

void icp_free_name_entries(name_entry *vec) {
	for (int i=0; vec[i].key != NULL || vec[i].val != NULL; i++) {
		icp_free_name_entry(vec[i]);
	}
	safe_free(vec);
}

void icp_free_name_entry(name_entry entry) {
	safe_free(entry.key);
	safe_free(entry.val);
}

int icp_new_cert_from_file(char *path, icp_cert **ret_certs, icp_errc **ret_errcs) {
	// Make buffers
	int buf_size = 64;
	icp_cert *certs = calloc(buf_size+1, sizeof(icp_cert));
	icp_errc *errcs = calloc(buf_size+1, sizeof(icp_errc));
	*ret_certs = certs;
	*ret_errcs = errcs;

	// Call go
	return NewCertificateFromFile(path, certs, errcs, buf_size);
}
