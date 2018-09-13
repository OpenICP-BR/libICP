/** @file */ 
#pragma once
#ifndef __LIBICP__
#define __LIBICP__

#include "stdlib.h"
#include "stdio.h"

// READ MAN PAGES !!!

typedef void* icp_cert;
typedef void* icp_errc;
typedef void* icp_err;
#ifndef __ICP__NAME_ENTRY__
#define __ICP__NAME_ENTRY__
typedef struct {
	char *key, *val;
} name_entry;
#endif

#ifdef __cplusplus
extern "C" {
#endif

char* icp_version();

int icp_errc_code(icp_errc errc);
char* icp_errc_code_str(icp_errc errc);
char* icp_err_str(icp_err err);
char* icp_cert_subject(icp_cert cert);
char* icp_cert_issuer(icp_cert cert);
name_entry* icp_cert_issuer_map(icp_cert cert);
name_entry* icp_cert_subject_map(icp_cert cert);
void icp_free_name_entries(name_entry *entries);
void icp_free_name_entry(name_entry entry);
int icp_new_cert_from_file(char *path, icp_cert **certs, icp_errc **errcs);

#ifdef __cplusplus
}
#endif
#endif //__LIBICP__