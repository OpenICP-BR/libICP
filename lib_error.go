package icp

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

type CodedError interface {
	Error() string
	ErrorCode() int
}

type MultiError struct {
	message    string
	code       int
	stack      []byte
	line       int
	file       string
	function   string
	parameters map[string]interface{}
	errors     []error
	locked     bool
}

func NewMultiError(message string, code int, parameters map[string]interface{}, errors []error, single_error error) MultiError {
	merr := MultiError{}
	merr.code = code
	merr.message = message
	merr.parameters = parameters
	merr.errors = errors
	if single_error != nil {
		if merr.errors == nil {
			merr.errors = make([]error, 1)
			merr.errors[0] = single_error
		}
	}
	merr.mark_position()
	return merr
}

func (merr MultiError) Error() string {
	ans := fmt.Sprintf("%s:%d:%s:%d %s", merr.function, merr.code, merr.file, merr.line, merr.message)
	// Print parameters
	if merr.parameters != nil && len(merr.parameters) > 0 {
		ans += "\nParameters:\n"
		for k, v := range merr.parameters {
			ans += fmt.Sprintf("\n\t%s: %+v", k, v)
		}
	}
	// Print encapsulated errors
	if merr.errors != nil && len(merr.errors) > 0 {
		ans += "\nErrors:\n"
		for _, err := range merr.errors {
			if err == nil {
				continue
			}
			tmp := err.Error()
			strings.Replace(tmp, "\n", "\n\t", -1)
			ans += "\n\t" + tmp
		}
	}
	// Print stack
	if merr.stack != nil {
		ans += "\nStack:\n" + string(merr.stack)
	}
	return ans
}

func (merr MultiError) ErrorCode() int {
	return merr.code
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
		merr.errors = make([]error, 0)
	}
	merr.errors = append(merr.errors, err)
	return nil
}

// Sets the line number and function to match where this function is called and prevents further editing.
func (merr *MultiError) Finish() {
	merr.mark_position()
	merr.locked = true
}

func (merr *MultiError) mark_position() {
	// Save execution stack
	merr.stack = debug.Stack()
	// Get information about who created this error
	pc, file, line, _ := runtime.Caller(2)
	merr.line = line
	// Print only the last part of the file path
	tmp := strings.Split(file, "/")
	merr.file = tmp[len(tmp)-1]
	// Try to get the function name
	f := runtime.FuncForPC(pc)
	if f != nil {
		merr.function = f.Name()
	}
}
