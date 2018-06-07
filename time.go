package icp

import (
	"encoding/asn1"
	"time"
)

// Also unmarshals UTCTime
type generalizedValidityT struct {
	RawContent    asn1.RawContent
	NotBeforeTime time.Time `asn1:"generalized"`
	NotAfterTime  time.Time `asn1:"generalized"`
}
