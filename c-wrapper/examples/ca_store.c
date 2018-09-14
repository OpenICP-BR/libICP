#include "stdio.h"
#include "libICP.h"

int main (int argc, char **argv) {
	icp_store store;

	store = icp_new_store(false);
	icp_store_debug_set(store, true);
	icp_store_download_all(store);
	return 0;
}