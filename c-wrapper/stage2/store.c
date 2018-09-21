#include "libICP.h"
#include "stage1.h"

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

const char* icp_store_cache_path(icp_store store) {
	return CAStoreCachePath(store);
}

void icp_store_cache_path_set(icp_store store, const char* path) {
	CAStoreCachePathSet(store, (char*) path);
}

icp_errc icp_store_download_all(icp_store store) {
	return CAStoreDownloadAll(store);
}

int icp_store_add_ca(icp_store store, icp_cert cert, icp_errc **errcs) {
	return CAStoreAddCA(store, cert, errcs);
}

int icp_store_add_testing_root_ca(icp_store store, icp_cert cert, icp_errc **errcs) {
	return CAStoreAddTestingRootCA(store, cert, errcs);	
}

icp_err icp_store_add_all_cas_from_dir(icp_store store, const char *path) {
	return CAStoreAddCAsFromDir(store, (char *) path);
}
