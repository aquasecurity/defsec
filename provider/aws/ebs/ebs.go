package ebs

import "github.com/aquasecurity/defsec/types"

type EBS struct {
	Volumes []Volume
}

type Volume struct {
	*types.Metadata
	Encryption Encryption
}

type Encryption struct {
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}
