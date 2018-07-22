package icp

import "github.com/gjvnq/asn1"

type EncapsulatedContentInfo struct {
	RawContent   asn1.RawContent
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,omitempty"`
	FallbackFile string
	hashes       map[string][]byte
}

func (encap EncapsulatedContentInfo) IsDetached() bool {
	return encap.EContent == nil
}

func (encap *EncapsulatedContentInfo) HashAs(alg_id AlgorithmIdentifier) ([]byte, CodedError) {
	if encap.hashes == nil {
		encap.hashes = make(map[string][]byte)
	}
	// Check if the hash was already calculated
	if ans, ok := encap.hashes[alg_id.ToHex()]; ok {
		return ans, nil
	}
	// Get hasher
	return nil, NewMultiError("HashAs not implemented", ERR_NOT_IMPLEMENTED, nil)
}

/*	According to RFC 5652 Section 5.2 Page 11 Paragraph 2:

	In the degenerate case where there are no signers, the
	EncapsulatedContentInfo value being "signed" is irrelevant.  In this
	case, the content type within the EncapsulatedContentInfo value being
	"signed" MUST be id-data (as defined in Section 4), and the content
	field of the EncapsulatedContentInfo value MUST be omitted.
*/
func (ec *EncapsulatedContentInfo) AdjustForNoSigners() {
	ec.EContentType = IdData()
	ec.EContent = nil
}
