#include "stdio.h"
#include "libICP.h"

int main () {
	icp_store store;

	store = icp_store_new(false);
	icp_store_debug_set(store, true);
	icp_errc err = icp_store_download_all(store);
	if (err != NULL) {
		printf("Error code:    %s\n", icp_errc_code_str(err));
		printf("Error message: %s\n", icp_err_str(err));
	}
	return 0;
}
