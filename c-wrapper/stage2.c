#include "libICP.h"
#include "stage1.h"

icp_cert icp_new_cert() {
	return NewCertificate();
}

char* icp_version() {
	return Version();
}

int icp_cerr_code(icp_cerr cerr) {
	return CodedErrorGetErrorInt(cerr);
}

char* icp_cerr_str(icp_cerr cerr) {
	return CodedErrorGetErrorStr(cerr);
}