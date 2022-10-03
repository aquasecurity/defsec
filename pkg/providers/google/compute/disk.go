package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Disk struct {
	Metadata   defsecTypes.Metadata
	Name       defsecTypes.StringValue
	Encryption DiskEncryption
}

type DiskEncryption struct {
	Metadata   defsecTypes.Metadata
	RawKey     defsecTypes.BytesValue
	KMSKeyLink defsecTypes.StringValue
}
