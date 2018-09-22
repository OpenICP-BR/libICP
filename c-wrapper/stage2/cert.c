#include "libICP.h"
#include "stage1.h"

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

icp_time icp_cert_not_before(icp_cert cert) {
	return CertNotBefore(cert);
}

icp_time icp_cert_not_after(icp_cert cert) {
	return CertNotAfter(cert);
}

char* icp_cert_fingerprint_human(icp_cert cert) {
	return CertFingerPrintHuman(cert);
}

char* icp_cert_fingerprint_alg(icp_cert cert) {
	return CertFingerPrintAlg(cert);
}

uint8_t* icp_cert_fingerprint(icp_cert cert, int *n) {
	return (uint8_t*) CertFingerPrint(cert, n);
}

bool icp_cert_is_self_signed(icp_cert cert) {
	return CertIsSelfSigned(cert);
}

bool icp_cert_is_ca(icp_cert cert) {
	return CertIsCA(cert);
}

void icp_free_cert(icp_cert cert) {
	FreeGoStuff(cert);
}

void icp_free_certs(icp_cert *certs) {
	for (int i=0; certs[i] != NULL; i++) {
		icp_free_cert(certs[i]);
	}
	free(certs);
}

int icp_new_cert_from_file(const char *path, icp_cert **certs, icp_errc **errcs) {
	return NewCertificateFromFile((char*) path, certs, errcs);
}

int icp_new_cert_from_bytes(uint8_t *data, int n, icp_cert **certs, icp_errc **errcs) {
	return NewCertificateFromBytes((char*) data, n, certs, errcs);
}
