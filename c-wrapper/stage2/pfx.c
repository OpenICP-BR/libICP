#include "libICP.h"
#include "stage1.h"

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
