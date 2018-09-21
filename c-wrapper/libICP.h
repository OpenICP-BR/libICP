/** @file */ 
#pragma once
#ifndef __LIBICP__
#define __LIBICP__

#include "stdlib.h"
#include "stdint.h"
#include "stdio.h"
#include "stdbool.h"

// READ MAN PAGES !!!

typedef void* icp_pfx;
typedef void* icp_store;
typedef void* icp_cert;
typedef void* icp_errc;
typedef void* icp_err;
typedef void* icp_any;
#ifndef __ICP__STRUCTS__
#define __ICP__STRUCTS__
typedef int64_t icp_time;
typedef struct {
	char *key, *val;
} icp_kvp;
#endif

#ifdef __cplusplus
extern "C" {
#endif

char* icp_version();
int icp_errc_code(icp_errc errc);
char* icp_errc_code_str(icp_errc errc);
char* icp_err_str(icp_err err);

void icp_free_err(icp_err err);
void icp_free_errs(icp_err *errs);
void icp_free_errc(icp_errc errc);
void icp_free_errcs(icp_errc *errcs);
int icp_len(icp_any *array);

// icp_cert as subject
char* icp_cert_subject(icp_cert cert);
char* icp_cert_issuer(icp_cert cert);
icp_kvp* icp_cert_issuer_map(icp_cert cert);
icp_kvp* icp_cert_subject_map(icp_cert cert);
icp_time icp_cert_not_before(icp_cert cert);
icp_time icp_cert_not_after(icp_cert cert);
char* icp_cert_fingerprint_human(icp_cert cert);
char* icp_cert_fingerprint_alg(icp_cert cert);
uint8_t* icp_cert_fingerprint(icp_cert cert, int *n);
bool icp_cert_is_self_signed(icp_cert cert);
bool icp_cert_is_ca(icp_cert cert);
void icp_free_certs(icp_cert *certs);
void icp_free_cert(icp_cert cert);
int icp_new_cert_from_file(const char *path, icp_cert **certs, icp_errc **errcs);
int icp_new_cert_from_bytes(uint8_t *data, int n, icp_cert **certs, icp_errc **errcs);

// icp_kvp as subject
void icp_free_kvps(icp_kvp *pairs);
void icp_free_kvp(icp_kvp pair);

// icp_store as subject
icp_store icp_store_new(bool auto_download);
int icp_store_verify(icp_store store, icp_cert cert, icp_cert **chain, icp_errc **errcs, icp_errc **warns);
bool icp_store_auto_download(icp_store store);
void icp_store_auto_download_set(icp_store store, bool flag);
bool icp_store_debug(icp_store store);
void icp_store_debug_set(icp_store store, bool flag);
const char* icp_store_cache_path(icp_store store);
void icp_store_cache_path_set(icp_store store, const char* path);
int icp_store_add_all_cas_from_dir(icp_store store, const char *path);
icp_errc icp_store_download_all(icp_store store);
int icp_store_add_ca(icp_store store, icp_cert cert, icp_errc **errcs);
int icp_store_add_testing_root_ca(icp_store store, icp_cert cert, icp_errc **errcs);
void icp_free_store(icp_store store);

// icp_pfx as subject
icp_pfx icp_pfx_from_file(const char *path, const char *password, icp_errc *errc);
icp_cert icp_pfx_cert(icp_pfx pfx);
bool icp_pfx_has_key(icp_pfx pfx);
bool icp_pfx_save_cert_to_file(icp_pfx pfx, const char *path, icp_errc *err);
bool icp_pfx_save_to_file(icp_pfx pfx, const char *path, const char *password, icp_errc *err);
void icp_free_pfx(icp_pfx pfx);

#ifdef __cplusplus
}
#endif
#endif //__LIBICP__
