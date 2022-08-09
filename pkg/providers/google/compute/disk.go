package compute

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Disk struct {
	types2.Metadata
	Name       types2.StringValue
	Encryption DiskEncryption
}

type DiskEncryption struct {
	types2.Metadata
	RawKey     types2.BytesValue
	KMSKeyLink types2.StringValue
}
