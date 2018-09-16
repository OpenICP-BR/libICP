#pragma once

#ifndef __ICP__STRUCTS__
#define __ICP__STRUCTS__
typedef struct {
	char *key, *val;
} icp_kvp;
#endif

void print_voids_ptr(void **vec);
icp_kvp* new_icp_kvps(int l);
void set_icp_kvp(icp_kvp *vec, int i, char *key, char *val);
void set_voids_ptr(void **vec, int i, void *ptr);
void** new_voids_ptr(int l);
