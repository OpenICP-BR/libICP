/** @file */ 
#pragma once
#ifndef __LIBICP__
#define __LIBICP__

#include "stdlib.h"
#include "stdio.h"

// READ MAN PAGES !!!

//! Pointer to a digital certificate.
typedef void* icp_cert;
//! Pointer to an error with a code.
typedef void* icp_errc;
//! Pointer to an uncoded error.
// \typedef abc
typedef void* icp_err;
typedef struct {
	char *key, *value;
} name_entry;

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

/*!
 * Loads one or more certificates from a DER or PEM encoded file.
 * @param path is the file path.
 * @param[out] certs is a pointer to an array of icp_cert.
 * @param[out] errcs is a pointer ro an array of icp_errc.
 * @return The number of errors.
 */
int icp_new_cert_from_file(char *path, icp_cert **certs, icp_errc **errcs);

#ifdef __cplusplus
}
#endif
#endif //__LIBICP__