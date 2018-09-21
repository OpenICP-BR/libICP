#include <libICP++.h>

using namespace ICP;

CodedError::CodedError(icp_errc new_errc_ptr) : Error(new_errc_ptr) {
	_errc_ptr = new_errc_ptr;
	if (_errc_ptr != NULL) {
		CodeStr = icp_errc_code_str(_errc_ptr);
		Code = icp_errc_code(_errc_ptr);
	}
}

CodedError::~CodedError() {
	icp_free_errc(_errc_ptr);
}
