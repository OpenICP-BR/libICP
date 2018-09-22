#include <libICP++.h>

namespace ICP {

Error::Error(icp_errc new_err_ptr) {
	_err_ptr = new_err_ptr;
	if (_err_ptr != NULL) {
		Message = icp_err_str(_err_ptr);
	}
}

bool Error::IsNull() {
	return _err_ptr == NULL;
}

Error::~Error() {
	icp_free_err(_err_ptr);
}
}
