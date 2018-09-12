#pragma once
#ifndef __LIBICP__
#define __LIBICP__

typedef void* icp_cert;
typedef void* icp_cerr;

#ifdef __cplusplus
extern "C" {
#endif

icp_cert new_icp_cert();
icp_cert icp_new_cert();
char* icp_version();
int icp_cerr_code(icp_cerr);
char* icp_cerr_str(icp_cerr cerr);

#ifdef __cplusplus
}
#endif
#endif //__LIBICP__