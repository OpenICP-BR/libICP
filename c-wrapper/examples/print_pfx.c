#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include <libICP.h>

char *getpass(const char *prompt);

int main (int argc, char **argv) {
	icp_cert cert;
	icp_errc err;
	icp_pfx pfx;
	icp_kvp *entries;
	char *passwd;

	if (argc < 2) {
		printf("You MUST inform the certificate path!\n");
		return 1;
	}

	passwd = getpass("PFX file password: ");
	pfx = icp_pfx_from_file(argv[1], passwd, &err);
	// the above function will erase memory
	printf("passwd = %s\n", passwd);
	printf("icp_pfx_has_key(pfx) = %d\n", icp_pfx_has_key(pfx));

	if (err != NULL) {
		printf("icp_errc_code(err)     = %d\n", icp_errc_code(err));
		printf("icp_errc_code_str(err) = %s\n", icp_errc_code_str(err));	
		printf("icp_err_str(err)       = %s\n", icp_err_str(err));	
		return 1;
	}

	cert = icp_pfx_cert(pfx);
	printf("icp_cert_subject(cert) = %s\n", icp_cert_subject(cert));
	printf("icp_cert_issuer(cert)  = %s\n", icp_cert_issuer(cert));
	entries = icp_cert_issuer_map(cert);
	printf("icp_cert_issuer_map(cert):\n");
	for (int j=0; entries[j].key != NULL; j++) {
		printf("\tKey: %s\tValue: %s\n", entries[j].key, entries[j].val);
	}
	icp_free_kvps(entries);

	entries = icp_cert_subject_map(cert);
	printf("icp_cert_subject_map(cert):\n");
	for (int j=0; entries[j].key != NULL; j++) {
		printf("\tKey: %s\tValue: %s\n", entries[j].key, entries[j].val);
	}
	icp_free_kvps(entries);

	return 0;
}
