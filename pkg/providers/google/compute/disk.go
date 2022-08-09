package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Disk struct {
	defsecTypes.Metadata
	Name       defsecTypes.StringValue
	Encryption DiskEncryption
}

type DiskEncryption struct {
	defsecTypes.Metadata
	RawKey     defsecTypes.BytesValue
	KMSKeyLink defsecTypes.StringValue
}
