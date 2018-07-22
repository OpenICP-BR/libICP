package icp

import "github.com/gjvnq/asn1"

type EncapsulatedContentInfo struct {
	RawContent    asn1.RawContent
	EContentType  asn1.ObjectIdentifier
	EContent      []byte `asn1:"explicit,optional,omitempty"`
	fallback_file string
	final_hash    []byte
}

func (encap EncapsulatedContentInfo) HashAs(alg_id AlgorithmIdentifier) {
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
