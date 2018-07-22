package iicp

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type hackStringS struct {
}

func (hs hackStringS) String() string {
	return "-"
}

func Test_NewMultiError_1(t *testing.T) {
	merr := NewMultiError("hi", ERR_OK, nil, "hi", errors.New("hi2"), 0, nil, hackStringS{}, []byte{1})
	merr.AppendError(nil)
	merr.AppendError(errors.New("hi"))
	merr.SetParam("pointer", nil)
	merr.SetParam("dat", []byte{1})
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
	assert.Equal(t, tmp[0], "github.com/gjvnq/libICP/iicp.Test_NewMultiError_1 (errors_test.go:?): ERR_OK: hi")
	assert.EqualValues(t, ERR_OK, merr.Code())
}

func Test_NewMultiError_2(t *testing.T) {
	merr := NewMultiError("hi", ERR_OK, nil)
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
	assert.Equal(t, tmp[0], "github.com/gjvnq/libICP/iicp.Test_NewMultiError_2 (errors_test.go:?): ERR_OK: hi")
	assert.EqualValues(t, ERR_OK, merr.Code())
}
