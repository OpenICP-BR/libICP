package libICP

import "strconv"

type ErrorCode int

const (
	ERR_OK = iota
	ERR_BAD_SIGNATURE
	ERR_BASIC_CONSTRAINTS_MAX_PATH_EXCEDED
	ERR_FAILED_ABS_PATH
	ERR_FAILED_HASH
	ERR_FAILED_TO_DECODE
	ERR_FAILED_TO_ENCODE
	ERR_FAILED_TO_OPEN_FILE
	ERR_FAILED_TO_SIGN
	ERR_FAILED_TO_WRITE_FILE
	ERR_FILE_NOT_EXISTS
	ERR_GEN_KEYS
	ERR_HTTP
	ERR_ISSUER_NOT_FOUND
	ERR_LOCKED_MULTI_ERROR
	ERR_MAX_DEPTH_REACHED
	ERR_NETWORK_ERROR
	ERR_NO_CERT_PATH
	ERR_NO_CONTENT
	ERR_NOT_AFTER_DATE
	ERR_NOT_BEFORE_DATE
	ERR_NOT_CA
	ERR_NOT_IMPLEMENTED
	ERR_PARSE_CERT
	ERR_PARSE_CRL
	ERR_PARSE_EXTENSION
	ERR_PARSE_PFX
	ERR_PARSE_RSA_PRIVKEY
	ERR_PARSE_RSA_PUBKEY
	ERR_READ_FILE
	ERR_REVOKED
	ERR_SECURE_RANDOM
	ERR_TEST_CA_IMPROPPER_NAME
	ERR_UNKOWN_ALGORITHM
	ERR_UNKOWN_REVOCATION_STATUS
	ERR_UNSUPORTED_CRITICAL_EXTENSION
	ERR_UNZIP_ERROR
)

var errors_map_string = map[ErrorCode]string{
	ERR_BAD_SIGNATURE:                      "ERR_BAD_SIGNATURE",
	ERR_BASIC_CONSTRAINTS_MAX_PATH_EXCEDED: "ERR_BASIC_CONSTRAINTS_MAX_PATH_EXCEDED",
	ERR_FAILED_ABS_PATH:                    "ERR_FAILED_ABS_PATH",
	ERR_FAILED_HASH:                        "ERR_FAILED_HASH",
	ERR_FAILED_TO_DECODE:                   "ERR_FAILED_TO_DECODE",
	ERR_FAILED_TO_ENCODE:                   "ERR_FAILED_TO_ENCODE",
	ERR_FAILED_TO_OPEN_FILE:                "ERR_FAILED_TO_OPEN_FILE",
	ERR_FAILED_TO_SIGN:                     "ERR_FAILED_TO_SIGN",
	ERR_FAILED_TO_WRITE_FILE:               "ERR_FAILED_TO_WRITE_FILE",
	ERR_FILE_NOT_EXISTS:                    "ERR_FILE_NOT_EXISTS",
	ERR_GEN_KEYS:                           "ERR_GEN_KEYS",
	ERR_HTTP:                               "ERR_HTTP",
	ERR_ISSUER_NOT_FOUND:                   "ERR_ISSUER_NOT_FOUND",
	ERR_LOCKED_MULTI_ERROR:                 "ERR_LOCKED_MULTI_ERROR",
	ERR_MAX_DEPTH_REACHED:                  "ERR_MAX_DEPTH_REACHED",
	ERR_NETWORK_ERROR:                      "ERR_NETWORK_ERROR",
	ERR_NO_CERT_PATH:                       "ERR_NO_CERT_PATH",
	ERR_NO_CONTENT:                         "ERR_NO_CONTENT",
	ERR_NOT_AFTER_DATE:                     "ERR_NOT_AFTER_DATE",
	ERR_NOT_BEFORE_DATE:                    "ERR_NOT_BEFORE_DATE",
	ERR_NOT_CA:                             "ERR_NOT_CA",
	ERR_NOT_IMPLEMENTED:                    "ERR_NOT_IMPLEMENTED",
	ERR_OK:                                 "ERR_OK",
	ERR_PARSE_CERT:                         "ERR_PARSE_CERT",
	ERR_PARSE_CRL:                          "ERR_PARSE_CRL",
	ERR_PARSE_EXTENSION:                    "ERR_PARSE_EXTENSION",
	ERR_PARSE_PFX:                          "ERR_PARSE_PFX",
	ERR_PARSE_RSA_PRIVKEY:                  "ERR_PARSE_RSA_PRIVKEY",
	ERR_PARSE_RSA_PUBKEY:                   "ERR_PARSE_RSA_PUBKEY",
	ERR_READ_FILE:                          "ERR_READ_CERT_FILE",
	ERR_REVOKED:                            "ERR_REVOKED",
	ERR_SECURE_RANDOM:                      "ERR_SECURE_RANDOM",
	ERR_TEST_CA_IMPROPPER_NAME:             "ERR_TEST_CA_IMPROPPER_NAME",
	ERR_UNKOWN_ALGORITHM:                   "ERR_UNKOWN_ALGORITHM",
	ERR_UNKOWN_REVOCATION_STATUS:           "ERR_UNKOWN_REVOCATION_STATUS",
	ERR_UNSUPORTED_CRITICAL_EXTENSION:      "ERR_UNSUPORTED_CRITICAL_EXTENSION",
	ERR_UNZIP_ERROR:                        "ERR_UNZIP_ERROR",
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
