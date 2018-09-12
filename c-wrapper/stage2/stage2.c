#include "libICP.h"
#include "stage1.h"

char* icp_version() {
	return Version();
}

int icp_cerr_code(icp_cerr cerr) {
	return CodedErrorGetErrorInt(cerr);
}

char* icp_cerr_code_str(icp_cerr cerr) {
	return CodedErrorGetErrorStr(cerr);
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

int icp_new_cert_from_file(char *path, icp_cert **ret_certs, icp_cerr **ret_cerrs) {
	// Make buffers
	int buf_size = 9;
	icp_cert *certs = calloc(buf_size+1, sizeof(icp_cert));
	icp_cerr *cerrs = calloc(buf_size+1, sizeof(icp_cerr));
	*ret_certs = certs;
	*ret_cerrs = cerrs;

	return NewCertificateFromFile(path, certs, cerrs, buf_size);
}
