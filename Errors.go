package libICP

import rawICP "github.com/gjvnq/libICP/rawICP"

type CodedError interface {
	error
	Code() rawICP.ErrorCode
	CodeString() string
}

// This is the same as CodedError. There are two names just to make the API more obvious to the reader when a functions returns an array of errors and an array of warnings.
type CodedWarning interface {
	CodedError
}

func rawICPCodedErrorSlice(errs []rawICP.CodedError) []CodedError {
	new_errs := make([]CodedError, len(errs))
	for i := range errs {
		new_errs[i] = CodedError(errs[i])
	}
	return new_errs
}

func rawICPCodedWarningSlice(warns []rawICP.CodedWarning) []CodedWarning {
	new_warns := make([]CodedWarning, len(warns))
	for i := range warns {
		new_warns[i] = CodedError(warns[i])
	}
	return new_warns
}
