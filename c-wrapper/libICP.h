#pragma once
#ifndef __LIBICP__
#define __LIBICP__

typedef void* icp_cert;

#ifdef __cplusplus
extern "C" {
#endif

icp_cert new_icp_cert();

#ifdef __cplusplus
}
#endif
#endif //__LIBICP__