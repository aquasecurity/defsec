package ec2

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Volume struct {
	types2.Metadata
	Encryption Encryption
}

type Encryption struct {
	types2.Metadata
	Enabled  types2.BoolValue
	KMSKeyID types2.StringValue
}
