#include <libICP++.h>

using namespace ICP;

Error::Error(icp_errc new_err_ptr) {
	_err_ptr = new_err_ptr;
	Message = icp_err_str(_err_ptr);
}

Error::~Error() {
	icp_free_err(_err_ptr);
}
