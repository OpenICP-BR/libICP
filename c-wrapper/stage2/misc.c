#include "libICP.h"
#include "stage1.h"

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

void icp_free_errs(icp_err *errs) {
	for (int i=0; errs[i] != NULL; i++) {
		FreeGoStuff(errs[i]);
	}
	free(errs);
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
	free(vec);
}

void icp_free_kvp(icp_kvp entry) {
	free(entry.key);
	free(entry.val);
}
