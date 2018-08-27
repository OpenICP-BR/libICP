package libICP

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"

	"github.com/OpenICP-BR/asn1"
)

type stringI interface {
	String() string
}

type CodedError interface {
	error
	Code() ErrorCode
	CodeString() string
}

// This is the same as CodedError. There are two names just to make the API more obvious to the reader when a functions returns an array of errors and an array of warnings.
type CodedWarning interface {
	CodedError
}

type pairErrorCodePos struct {
	Error    interface{}
	Line     int
	File     string
	Function string
}

type MultiError struct {
	message    string
	code       ErrorCode
	line       int
	file       string
	function   string
	parameters map[string]interface{}
	errors     []pairErrorCodePos
	locked     bool
}

func NewMultiError(message string, code ErrorCode, parameters map[string]interface{}, errors ...interface{}) MultiError {
	merr := MultiError{}
	merr.code = code
	merr.message = message
	merr.parameters = parameters
	merr.errors = make([]pairErrorCodePos, len(errors))
	for i := 0; i < len(errors); i++ {
		merr.errors[i].Error = errors[i]
		merr.errors[i].Function, merr.errors[i].File, merr.errors[i].Line = get_stack_pos(2)
	}
	merr.mark_position()
	return merr
}

func (perr pairErrorCodePos) String() string {
	return fmt.Sprintf("%s:%s:%d %s", perr.Function, perr.File, perr.Line, perr.Error)
}

func (merr MultiError) Error() string {
	ans := fmt.Sprintf("%s (%s:%d): %s: %s", merr.function, merr.file, merr.line, merr.code, merr.message)
	// Print parameters
	if merr.parameters != nil && len(merr.parameters) > 0 {
		ans += "\nParameters:"
		for k, v := range merr.parameters {
			switch v := v.(type) {
			case []byte:
				tmp := base64.StdEncoding.EncodeToString(v)
				ans += fmt.Sprintf("\n\t%s:(base64): %+v", k, tmp)
			case asn1.RawContent:
				tmp := base64.StdEncoding.EncodeToString(v)
				ans += fmt.Sprintf("\n\t%s:(base64): %+v", k, tmp)
			default:
				ans += fmt.Sprintf("\n\t%s: %+v", k, v)
			}
		}
	}
	// Print encapsulated errors
	if merr.errors != nil && len(merr.errors) > 0 {
		ans += "\nErrors: ["
		for _, err := range merr.errors {
			if err.Error == nil {
				continue
			}
			tmp := "-"
			switch terr := err.Error.(type) {
			case error:
				tmp = terr.Error()
			case stringI:
				tmp = terr.String()
			default:
				tmp = fmt.Sprintf("%+v", terr)
			}
			tmp = strings.Replace(tmp, "\n", "\n\t", -1)
			tmp = strings.Replace(tmp, "\t", "\t\t", -1)
			ans += fmt.Sprintf("\n\t(%s:%s:%d) %s", err.Function, err.File, err.Line, tmp)
		}
		ans += "\n]"
	}
	return ans
}

func (merr MultiError) Code() ErrorCode {
	return merr.code
}

func (merr MultiError) CodeString() string {
	return merr.code.String()
}

func (merr *MultiError) SetParam(key string, val interface{}) error {
	if merr.locked {
		return NewMultiError("attempted to edit locekd MultiError", ERR_LOCKED_MULTI_ERROR, nil, nil, nil)
	}
	if merr.parameters == nil {
		merr.parameters = make(map[string]interface{})
	}
	merr.parameters[key] = val
	return nil
}

func (merr *MultiError) AppendError(err error) error {
	if merr.locked {
		return NewMultiError("attempted to edit locekd MultiError", ERR_LOCKED_MULTI_ERROR, nil, nil, nil)
	}
	if merr.errors == nil {
		merr.errors = make([]pairErrorCodePos, 0)
	}
	p := pairErrorCodePos{}
	p.Error = err
	p.Function, p.File, p.Line = get_stack_pos(2)
	merr.errors = append(merr.errors, p)
	return nil
}

// Sets the line number and function to match where this function is called and prevents further editing. Also returns itself.
func (merr *MultiError) Finish() *MultiError {
	merr.mark_position()
	merr.locked = true
	return merr
}

func get_stack_pos(depth int) (string, string, int) {
	function := "?"
	// Get information about who created this error
	pc, file, line, _ := runtime.Caller(depth)
	// Print only the last part of the file path
	tmp := strings.Split(file, "/")
	file = tmp[len(tmp)-1]
	// Try to get the function name
	f := runtime.FuncForPC(pc)
	if f != nil {
		function = f.Name()
	}

	return function, file, line
}

func (merr *MultiError) mark_position() {
	// Get information about who created this error
	merr.function, merr.file, merr.line = get_stack_pos(3)
}
