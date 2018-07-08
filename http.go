package icp

import (
	"io/ioutil"
	"net/http"
	"time"
)

func http_get(url string) ([]byte, int64, CodedError) {
	// Get the data
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(ALL_CAs_ZIP_URL)
	if err != nil {
		merr := NewMultiError("failed to use GET method", ERR_HTTP, nil, err)
		merr.SetParam("URL", url)
		return nil, 0, merr
	}
	raw, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		merr := NewMultiError("failed to read http response", ERR_HTTP, nil, err)
		merr.SetParam("URL", url)
		return nil, 0, merr
	}

	return raw, resp.ContentLength, nil
}
