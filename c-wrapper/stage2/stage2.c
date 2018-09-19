#include "libICP.h"
#include "stage1.h"

void safe_free(void *ptr) {
	if (ptr != NULL) {
		free(ptr);
	}
}

void garbage_fill(char *str) {
	if (str == NULL) {
		return;
	}
	for (int i=1; str[i] != 0; i++) {
		str[i] ^= str[i-1];
	}
	str[0] = 0;
}

int icp_len(icp_any *array) {
	int i;
	for (i=0; array[i] != NULL; i++) {
	}
	return i;
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

icp_time icp_cert_not_before(icp_cert cert) {
	return CertNotBefore(cert);
}

icp_time icp_cert_not_after(icp_cert cert) {
	return CertNotAfter(cert);
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
	safe_free(certs);
}

void icp_free_errs(icp_err *errs) {
	for (int i=0; errs[i] != NULL; i++) {
		FreeGoStuff(errs[i]);
	}
	safe_free(errs);
}

void icp_free_errcs(icp_errc *errcs) {
	icp_free_errs((icp_err*) errcs);
}

void icp_free_errc(icp_errc errc) {
	icp_free_err((icp_err) errc);
}

void icp_free_store(icp_store store) {
	FreeGoStuff(store);
}

void icp_free_err(icp_err err) {
	FreeGoStuff(err);
}

void icp_free_pfx(icp_pfx pfx) {
	FreeGoStuff(pfx);
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

int icp_new_cert_from_file(const char *path, icp_cert **certs, icp_errc **errcs) {
	return NewCertificateFromFile((char*) path, certs, errcs);
}

int icp_new_cert_from_bytes(uint8_t *data, int n, icp_cert **certs, icp_errc **errcs) {
	return NewCertificateFromBytes((char*) data, n, certs, errcs);
}

icp_store icp_store_new(bool auto_download) {
	return NewCAStore(auto_download);
}

int icp_store_verify(icp_store store, icp_cert cert, icp_cert **chain, icp_errc **errcs, icp_errc **warns) {
	return CAStoreVerifyCert(store, cert, chain, errcs, warns);
}

bool icp_store_auto_download(icp_store store) {
	return CAStoreAutoDownload(store);
}

void icp_store_auto_download_set(icp_store store, bool flag) {
	CAStoreAutoDownloadSet(store, flag);
}

bool icp_store_debug(icp_store store) {
	return CAStoreDebug(store);
}

void icp_store_debug_set(icp_store store, bool flag) {
	CAStoreDebugSet(store, flag);
}

void icp_store_download_all(icp_store store) {
	CAStoreDownloadAll(store);
}

int icp_store_add_ca(icp_store store, icp_cert cert, icp_errc **errcs) {
	return CAStoreAddCA(store, cert, errcs);
}

int icp_store_add_testing_root_ca(icp_store store, icp_cert cert, icp_errc **errcs) {
	return CAStoreAddTestingRootCA(store, cert, errcs);	
}

icp_pfx icp_pfx_from_file(const char *path, const char *password, icp_errc *err) {
	return NewPFXFromFile((char*) path, (char*) password, err);
}

icp_cert icp_pfx_cert(icp_pfx pfx) {
	return PFXCert(pfx);
}

bool icp_pfx_has_key(icp_pfx pfx) {
	return PFXHasKey(pfx);
}

bool icp_pfx_save_cert_to_file(icp_pfx pfx, const char *path, icp_errc *err) {
	return PFXSaveCertToFile(pfx, (char*) path, err);
}

bool icp_pfx_save_to_file(icp_pfx pfx, const char *path, const char *password, icp_errc *err) {
	return PFXSaveToFile(pfx, (char*) path, (char*) password, err);
}
