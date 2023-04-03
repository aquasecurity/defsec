package sslcertificate

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ServerCertificate struct {
	Metadata   defsecTypes.Metadata
	Expiration defsecTypes.TimeValue
}
