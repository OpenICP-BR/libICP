package icp

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"regexp"
	"strings"
	"testing"
)

type hackStringS struct {
}

func (hs hackStringS) String() string {
	return "-"
}

func Test_NewMultiError_1(t *testing.T) {
	merr := NewMultiError("hi", 42, nil, "hi", errors.New("hi2"), 0, nil, hackStringS{})
	merr.AppendError(nil)
	merr.AppendError(errors.New("hi"))
	merr.SetParam("pointer", nil)
	merr.Finish()
	err1 := merr.AppendError(nil)
	assert.NotNil(t, err1)
	err2 := merr.AppendError(errors.New("hi"))
	assert.NotNil(t, err2)
	merr.AppendError(errors.New("hi"))
	merr.SetParam("str", "hi")

	tmp := strings.Split(merr.Error(), "\n")
	r := regexp.MustCompile("[.]go:[0-9]*")
	tmp[0] = r.ReplaceAllString(tmp[0], ".go:?")
	assert.Equal(t, "github.com/gjvnq/libICP.Test_NewMultiError_1:42:lib_error_test.go:? hi", tmp[0])
	assert.Equal(t, 42, merr.ErrorCode())
}

func Test_NewMultiError_2(t *testing.T) {
	merr := NewMultiError("hi", 42, nil)
	merr.AppendError(nil)
	merr.AppendError(errors.New("hi"))
	merr.SetParam("pointer", nil)
	merr.Finish()
	err1 := merr.AppendError(nil)
	assert.NotNil(t, err1)
	err2 := merr.AppendError(errors.New("hi"))
	assert.NotNil(t, err2)
	merr.AppendError(errors.New("hi"))
	merr.SetParam("str", "hi")

	tmp := strings.Split(merr.Error(), "\n")
	r := regexp.MustCompile("[.]go:[0-9]*")
	tmp[0] = r.ReplaceAllString(tmp[0], ".go:?")
	assert.Equal(t, "github.com/gjvnq/libICP.Test_NewMultiError_2:42:lib_error_test.go:? hi", tmp[0])
	assert.Equal(t, 42, merr.ErrorCode())
}
