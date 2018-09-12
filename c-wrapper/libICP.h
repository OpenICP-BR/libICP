/** @file */ 
#pragma once
#ifndef __LIBICP__
#define __LIBICP__

#include "stdlib.h"
#include "stdio.h"

//! Pointer to a digital certificate.
typedef void* icp_cert;
//! Pointer to a coded error.
typedef void* icp_cerr;
//! Pointer to an uncoded error.
// \typedef abc
typedef void* icp_err;
typedef struct {
	char *key, *value;
} name_entry;

#ifdef __cplusplus
extern "C" {
#endif

//! Returns a string with the version of this library.
char* icp_version();

int icp_cerr_code(icp_cerr);
char* icp_cerr_code_str(icp_cerr cerr);
char* icp_err_str(icp_err err);
char* icp_cert_subject(icp_cert cert);
char* icp_cert_issuer(icp_cert cert);
name_entry* icp_cert_issuer_map(icp_cert cert);
name_entry* icp_cert_subject_map(icp_cert cert);

/*!
 * Loads one or more certificates from a DER or PEM encoded file.
 * @param path is the file path.
 * @param[out] certs is a pointer to an array of icp_cert.
 * @param[out] cerrs is a pointer ro an array of icp_cerr.
 * @return The number of errors.
 */
int icp_new_cert_from_file(char *path, icp_cert **certs, icp_cerr **cerrs);

#ifdef __cplusplus
}
#endif
#endif //__LIBICP__