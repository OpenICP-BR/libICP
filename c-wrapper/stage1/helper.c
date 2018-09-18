#include "helper.h"
#include "stdlib.h"
#include "stdint.h"
#include "stdio.h"

void set_voids_ptr(void **vec, int i, void *ptr) {
	vec[i] = ptr;
}

void set_icp_kvp(icp_kvp *vec, int i, char *key, char *val) {
	vec[i].key = key;
	vec[i].val = val;
}

char char_at(char *str, int i) {
	return str[i];
}

icp_kvp* new_icp_kvps(int l) {
	return calloc(l+1, sizeof(icp_kvp));
}

void** new_voids_ptr(int l) {
	return calloc(l+1, sizeof(void*));
}

void print_voids_ptr(void **vec) {
	printf("print_voids_ptr(%p): ", (void *)vec);
	for (int i=0; vec != NULL && vec[i] != NULL; i++) {
		printf("%p ", vec[i]);
	}
	printf("\n");
}
