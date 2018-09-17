#include "stdio.h"
#include "libICP.h"

int main (int argc, char **argv) {
	icp_cert *certs;
	icp_errc *errcs;
	icp_kvp *entries;
	int ok;

	if (argc < 2) {
		printf("You MUST inform the certificate path!\n");
		return 1;
	}

	ok = icp_new_cert_from_file(argv[1], &certs, &errcs);
	printf("icp_new_cert_from_file(...) = %d\n", ok);
	printf("certs    = %p errcs    = %p\n", (void*) certs, (void*) errcs);
	printf("certs[0] = %p errcs[0] = %p\n", certs[0], errcs[0]);
	for (int i=0; errcs != NULL && errcs[i] != NULL; i++) {
		printf("icp_errc_code(errcs[%d])     = %d\n", i, icp_errc_code(errcs[i]));
		printf("icp_errc_code_str(errcs[%d]) = %s\n", i, icp_errc_code_str(errcs[i]));	
		printf("icp_err_str(errcs[%d])       = %s\n", i, icp_err_str(errcs[i]));	
	}
	for (int i=0; certs != NULL && certs[i] != NULL; i++) {
		printf("icp_cert_subject(certs[%d]) = %s\n", i, icp_cert_subject(certs[i]));
		printf("icp_cert_issuer(certs[%d])  = %s\n", i, icp_cert_issuer(certs[i]));
		entries = icp_cert_issuer_map(certs[i]);
		printf("icp_cert_issuer_map(certs[%d]):\n", i);
		for (int j=0; entries[j].key != NULL; j++) {
			printf("\tKey: %s\tValue: %s\n", entries[j].key, entries[j].val);
		}
		icp_free_kvps(entries);

		entries = icp_cert_subject_map(certs[i]);
		printf("icp_cert_subject_map(certs[%d]):\n", i);
		for (int j=0; entries[j].key != NULL; j++) {
			printf("\tKey: %s\tValue: %s\n", entries[j].key, entries[j].val);
		}
		icp_free_kvps(entries);
	}
	return 0;
}
