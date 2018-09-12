#include "stdio.h"
#include "libICP.h"

int main (int argc, char **argv) {
	icp_cert *certs;
	icp_cerr *cerrs;
	int ok;

	if (argc < 2) {
		printf("You MUST inform the certificate path!\n");
		return 1;
	}

	ok = icp_new_cert_from_file(argv[1], &certs, &cerrs);
	printf("icp_new_cert_from_file(...) = %d\n", ok);
	for (int i=0; cerrs != NULL && cerrs[i] != NULL; i++) {
		printf("icp_cerr_code(cerrs[%d])     = %d\n", i, icp_cerr_code(cerrs[i]));
		printf("AAA\n");
		printf("icp_cerr_code_str(cerrs[%d]) = %s\n", i, icp_cerr_code_str(cerrs[i]));	
		printf("icp_err_str(cerrs[%d])       = %s\n", i, icp_err_str(cerrs[i]));	
	}
	for (int i=0; certs != NULL && certs[i] != NULL; i++) {
		printf("icp_cert_subject(certs[%d]) = %s\n", i, icp_cert_subject(certs[0]));
		printf("icp_cert_issuer(certs[%d])  = %s\n", i, icp_cert_issuer(certs[0]));
	}
	return 0;
}