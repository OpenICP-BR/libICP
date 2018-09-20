#include <libICP++.h>

using namespace ICP;

PFX::PFX(icp_pfx new_pfx_ptr) : Cert(icp_pfx_cert(new_pfx_ptr)) {
	_pfx_ptr = new_pfx_ptr;
}

PFX::~PFX() {
	icp_free_pfx(_pfx_ptr);
}

bool PFX::HasKey() {
	return icp_pfx_has_key(_pfx_ptr);
}

PFX LoadPFXFromFile(std::string path, std::string password, CodedError &errc) {
	icp_errc errc_ptr;
	icp_pfx pfx = icp_pfx_from_file(path.c_str(), password.c_str(), &errc_ptr);
	if (errc_ptr == NULL) {
		errc = NULL;
	} else {
		errc = CodedError(errc_ptr);
		return NULL;
	}

	return PFX(pfx);
}

CodedError PFX::SaveCertToFile(std::string path) {
	icp_errc errc_ptr;
	icp_pfx_save_cert_to_file(_pfx_ptr, path.c_str(), &errc_ptr);
	return CodedError(errc_ptr);
}

CodedError PFX::SaveToFile(std::string path, std::string password) {
	icp_errc errc_ptr;
	icp_pfx_save_to_file(_pfx_ptr, path.c_str(), password.c_str(), &errc_ptr);
	return CodedError(errc_ptr);
}
