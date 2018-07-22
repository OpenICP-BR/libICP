package icp

import "strconv"

type ErrorCode int

const (
	ERR_OK = iota
	ERR_NO_CERT_PATH
	ERR_ISSUER_NOT_FOUND
	ERR_LOCKED_MULTI_ERROR
	ERR_MAX_DEPTH_REACHED
	ERR_PARSE_CERT
	ERR_PARSE_RSA_PUBKEY
	ERR_READ_CERT_FILE
	ERR_NOT_BEFORE_DATE
	ERR_NOT_AFTER_DATE
	ERR_BAD_SIGNATURE
	ERR_NOT_IMPLEMENTED
	ERR_UNKOWN_ALGORITHM
	ERR_UNSUPORTED_CRITICAL_EXTENSION
	ERR_PARSE_EXTENSION
	ERR_TEST_CA_IMPROPPER_NAME
	ERR_NOT_CA
	ERR_BASIC_CONSTRAINTS_MAX_PATH_EXCEDED
	ERR_NETWORK_ERROR
	ERR_UNZIP_ERROR
	ERR_REVOKED
	ERR_UNKOWN_REVOCATION_STATUS
	ERR_PARSE_CRL
	ERR_HTTP
)

var errors_map_string = map[ErrorCode]string{
	ERR_OK:                                 "ERR_OK",
	ERR_NO_CERT_PATH:                       "ERR_NO_CERT_PATH",
	ERR_ISSUER_NOT_FOUND:                   "ERR_ISSUER_NOT_FOUND",
	ERR_LOCKED_MULTI_ERROR:                 "ERR_LOCKED_MULTI_ERROR",
	ERR_MAX_DEPTH_REACHED:                  "ERR_MAX_DEPTH_REACHED",
	ERR_PARSE_CERT:                         "ERR_PARSE_CERT",
	ERR_PARSE_RSA_PUBKEY:                   "ERR_PARSE_RSA_PUBKEY",
	ERR_READ_CERT_FILE:                     "ERR_READ_CERT_FILE",
	ERR_NOT_BEFORE_DATE:                    "ERR_NOT_BEFORE_DATE",
	ERR_NOT_AFTER_DATE:                     "ERR_NOT_AFTER_DATE",
	ERR_BAD_SIGNATURE:                      "ERR_BAD_SIGNATURE",
	ERR_NOT_IMPLEMENTED:                    "ERR_NOT_IMPLEMENTED",
	ERR_UNKOWN_ALGORITHM:                   "ERR_UNKOWN_ALGORITHM",
	ERR_UNSUPORTED_CRITICAL_EXTENSION:      "ERR_UNSUPORTED_CRITICAL_EXTENSION",
	ERR_PARSE_EXTENSION:                    "ERR_PARSE_EXTENSION",
	ERR_TEST_CA_IMPROPPER_NAME:             "ERR_TEST_CA_IMPROPPER_NAME",
	ERR_NOT_CA:                             "ERR_NOT_CA",
	ERR_BASIC_CONSTRAINTS_MAX_PATH_EXCEDED: "ERR_BASIC_CONSTRAINTS_MAX_PATH_EXCEDED",
	ERR_NETWORK_ERROR:                      "ERR_NETWORK_ERROR",
	ERR_UNZIP_ERROR:                        "ERR_UNZIP_ERROR",
	ERR_REVOKED:                            "ERR_REVOKED",
	ERR_UNKOWN_REVOCATION_STATUS:           "ERR_UNKOWN_REVOCATION_STATUS",
	ERR_PARSE_CRL:                          "ERR_PARSE_CRL",
	ERR_HTTP:                               "ERR_HTTP",
}

func (err ErrorCode) String() string {
	ans, ok := errors_map_string[err]
	if !ok {
		ans = "ERR_" + strconv.Itoa(int(err))
	}
	return ans
}

type CRLStatus int

const (
	CRL_UNSURE_OR_NOT_FOUND = 0
	// CRL_NOT_REVOKED is also used when the CA offers no means to check revocation status.
	CRL_NOT_REVOKED = 1
	CRL_REVOKED     = 2
)

var crl_map_string = map[CRLStatus]string{
	CRL_UNSURE_OR_NOT_FOUND: "CRL_UNSURE_OR_NOT_FOUND",
	CRL_NOT_REVOKED:         "CRL_NOT_REVOKED",
	CRL_REVOKED:             "CRL_REVOKED",
}

func (err CRLStatus) String() string {
	ans, ok := crl_map_string[err]
	if !ok {
		ans = "CRL_" + strconv.Itoa(int(err))
	}
	return ans
}
