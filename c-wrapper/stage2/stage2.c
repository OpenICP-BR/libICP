#include "libICP.h"
#include "stage1.h"

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

int icp_new_cert_from_file(char *path, icp_cert **ret_certs, icp_errc **ret_errcs) {
	// Make buffers
	int buf_size = 64;
	icp_cert *certs = calloc(buf_size+1, sizeof(icp_cert));
	icp_errc *errcs = calloc(buf_size+1, sizeof(icp_errc));
	*ret_certs = certs;
	*ret_errcs = errcs;

	return NewCertificateFromFile(path, certs, errcs, buf_size);
}
