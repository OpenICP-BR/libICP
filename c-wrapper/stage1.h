/* Created by "go tool cgo" - DO NOT EDIT. */

/* package github.com/OpenICP-BR/libICP/c-wrapper/stage1 */


#line 1 "cgo-builtin-prolog"

#include <stddef.h> /* for ptrdiff_t below */

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

typedef struct { const char *p; ptrdiff_t n; } _GoString_;

#endif

/* Start of preamble from import "C" comments.  */


#line 3 "/Users/gqueiroz/go/src/github.com/OpenICP-BR/libICP/c-wrapper/stage1/ca-store.go"
 #include "helper.h"

#line 1 "cgo-generated-wrapper"

#line 3 "/Users/gqueiroz/go/src/github.com/OpenICP-BR/libICP/c-wrapper/stage1/cert.go"
 #include "helper.h"

#line 1 "cgo-generated-wrapper"

#line 3 "/Users/gqueiroz/go/src/github.com/OpenICP-BR/libICP/c-wrapper/stage1/main.go"

 #include "helper.h"

#line 1 "cgo-generated-wrapper"

#line 3 "/Users/gqueiroz/go/src/github.com/OpenICP-BR/libICP/c-wrapper/stage1/pfx.go"
 #include "helper.h"

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

typedef _GoString_ GoString;
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


extern GoUint8 CAStoreAutoDownload(void* p0);

extern void CAStoreAutoDownloadSet(void* p0, GoUint8 p1);

extern GoUint8 CAStoreDebug(void* p0);

extern void CAStoreDebugSet(void* p0, GoUint8 p1);

extern void* NewCAStore(GoUint8 p0);

extern int CAStoreVerifyCert(void* p0, void* p1, void*** p2, void*** p3, void*** p4);

extern void CAStoreDownloadAll(void* p0);

extern char* CertSubject(void* p0);

extern icp_kvp* CertSubjectMap(void* p0);

extern icp_kvp* CertIssuerMap(void* p0);

extern char* CertIssuer(void* p0);

extern GoInt64 CertNotBefore(void* p0);

extern GoInt64 CertNotAfter(void* p0);

extern GoUint8 CertIsCA(void* p0);

extern GoUint8 CertIsSelfSigned(void* p0);

extern int NewCertificateFromFile(char* p0, void*** p1, void*** p2);

extern void FreeGoStuff(void* p0);

extern char* Version();

extern char* CodedErrorGetErrorStr(void* p0);

extern int CodedErrorGetErrorInt(void* p0);

extern char* ErrorStr(void* p0);

extern void* NewPFXFromFile(char* p0, char* p1, void** p2);

extern void* PFXCert(void* p0);

extern GoUint8 PFXHasKey(void* p0);

extern GoUint8 PFXSaveCertToFile(void* p0, char* p1, void** p2);

extern GoUint8 PFXSaveToFile(void* p0, char* p1, char* p2, void** p3);

#ifdef __cplusplus
}
#endif
