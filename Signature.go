package libICP

import "time"

// Represents a .p7s file containing one or more signatures and, sometimes, the content being signed.
type MultSignature struct {
	base signed_data_raw

	FilePath        string
	FileName        string
	ContentFilePath string
	ContentFileName string
	ContentAttached []byte
	Signatures      []Signature
}

type Signature struct {
	base signer_info_raw

	Signer      Certificate
	SigningTime time.Time
	// Format: "[ISO 3166-1 numeric]:[Text]" Ex: "076:Brasília-DF"
	SignerLocation string
	// Possible values: proofOfOrigin, proofOfReceipt, proofOfDelivery, proofOfSender, proofOfApproval, proofOfCreation (or the OID for unknown commitment types)
	Commitment   string
	CounterSigns []Signature
	Status       SignatureCheck
}

// Will attempt to save as a detached signature with file name "[content file with extension].sig" Ex: "contract.txt.sig"
func (msig *MultSignature) SaveToP7SFile() CodedError {
	return nil
}

// Verify all signatures recursively
func (msig *MultSignature) CheckAll(store *CAStore) CodedError {
	return nil
}

type SignatureCheck struct {
	Integrity       bool
	RootCA          string
	CRL_Status      CRLStatus
	SignerCertError CodedError
	PolicyErrors    []CodedError
}

func (sig SignatureCheck) IsSignerCertValid() bool {
	return sig.SignerCertError == nil
}

func (sig SignatureCheck) IsPolicyCompliant() bool {
	return len(sig.PolicyErrors) == 0
}
