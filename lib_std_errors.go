package icp

// Just a list of error and warning codes that be used in this library. The names are "equal" to their values so printing them is easier.
const (
	ERR_NO_CERT_PATH                       = "ERR_NO_CERT_PATH"
	ERR_ISSUER_NOT_FOUND                   = "ERR_ISSUER_NOT_FOUND"
	ERR_LOCKED_MULTI_ERROR                 = "ERR_LOCKED_MULTI_ERROR"
	ERR_MAX_DEPTH_REACHED                  = "ERR_MAX_DEPTH_REACHED"
	ERR_PARSE_CERT                         = "ERR_PARSE_CERT"
	ERR_PARSE_RSA_PUBKEY                   = "ERR_PARSE_RSA_PUBKEY"
	ERR_READ_CERT_FILE                     = "ERR_READ_CERT_FILE"
	ERR_NOT_BEFORE_DATE                    = "ERR_NOT_BEFORE_DATE"
	ERR_NOT_AFTER_DATE                     = "ERR_NOT_AFTER_DATE"
	ERR_BAD_SIGNATURE                      = "ERR_BAD_SIGNATURE"
	ERR_NOT_IMPLEMENTED                    = "ERR_NOT_IMPLEMENTED"
	ERR_UNKOWN_ALGORITHM                   = "ERR_UNKOWN_ALGORITHM"
	ERR_UNSUPORTED_CRITICAL_EXTENSION      = "ERR_UNSUPORTED_CRITICAL_EXTENSION"
	ERR_PARSE_EXTENSION                    = "ERR_PARSE_EXTENSION"
	ERR_TEST_CA_IMPROPPER_NAME             = "ERR_TEST_CA_IMPROPPER_NAME"
	ERR_NOT_CA                             = "ERR_NOT_CA"
	ERR_BASIC_CONSTRAINTS_MAX_PATH_EXCEDED = "ERR_BASIC_CONSTRAINTS_MAX_PATH_EXCEDED"
	ERR_NETWORK_ERROR                      = "ERR_NETWORK_ERROR"
	ERR_UNZIP_ERROR                        = "ERR_UNZIP_ERROR"
)
