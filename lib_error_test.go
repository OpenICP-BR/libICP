package icp

import (
	"github.com/stretchr/testify/assert"
	"regexp"
	"strings"
	"testing"
)

func Test_NewMultiError_1(t *testing.T) {
	merr := NewMultiError("hi", 42, nil, nil)
	tmp := strings.Split(merr.Error(), "\n")
	r := regexp.MustCompile("[.]go:[0-9]*")
	tmp[0] = r.ReplaceAllString(tmp[0], ".go:?")
	assert.Equal(t, "github.com/gjvnq/libICP.Test_NewMultiError_1:42:lib_error_test.go:? hi", tmp[0])
}
