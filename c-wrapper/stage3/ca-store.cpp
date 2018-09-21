#include <libICP++.h>

using std::vector;
using std::string;
using namespace ICP;

CAStore::CAStore() {
	_store_ptr = icp_store_new(false);
}

CAStore::CAStore(bool AutoDownload) {
	_store_ptr = icp_store_new(AutoDownload);
}

CAStore::~CAStore() {
	icp_free_store(_store_ptr);
}

void CAStore::SetDebug(bool flag) {
	icp_store_debug_set(_store_ptr, flag);
}

void CAStore::SetAutoDownload(bool flag) {
	icp_store_auto_download_set(_store_ptr, flag);
}

void CAStore::SetCachePath(string new_path) {
	icp_store_cache_path_set(_store_ptr, new_path.c_str());
}

bool CAStore::GetDebug() {
	return icp_store_debug(_store_ptr);
}

bool CAStore::GetAutoDownload() {
	return icp_store_auto_download(_store_ptr);
}

string CAStore::GetCachePath() {
	return string(icp_store_cache_path(_store_ptr));
}

vector<CodedError> CAStore::AddCA(Cert cert) {
	icp_errc *errcs_ptr;
	vector<CodedError> errs;

	icp_store_add_ca(cert._cert_ptr, cert._cert_ptr, &errcs_ptr);
	
	for (int i=0; errcs_ptr[i] != NULL; i++) {
		errs.push_back(CodedError(errcs_ptr[i]));
	}

	return errs;
}

vector<CodedError> CAStore::AddTestingRootCA(Cert cert) {
	icp_errc *errcs_ptr;
	vector<CodedError> errs;

	icp_store_add_testing_root_ca(cert._cert_ptr, cert._cert_ptr, &errcs_ptr);
	
	for (int i=0; errcs_ptr[i] != NULL; i++) {
		errs.push_back(CodedError(errcs_ptr[i]));
	}

	return errs;
}

CodedError CAStore::DownloadAll() {
	icp_errc errc_ptr = icp_store_download_all(_store_ptr);
	return CodedError(errc_ptr);
}

Error CAStore::AddAllCAsFromDir(string path) {
	return Error(icp_store_add_all_cas_from_dir(_store_ptr, path.c_str()));
}

void CAStore::AddAllCAsFromDirParallel(string path) {
	icp_store_add_all_cas_from_dir_parallel(_store_ptr, path.c_str());
}
