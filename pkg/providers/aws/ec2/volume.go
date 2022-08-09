package ec2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Volume struct {
	defsecTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}
