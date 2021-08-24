package compute

import "github.com/aquasecurity/defsec/definition"

type Disk struct {
	Name       definition.StringValue
	Encryption DiskEncryption
}

type DiskEncryption struct {
	RawKey     definition.BytesValue
	KMSKeyLink definition.StringValue
}

func (e *DiskEncryption) UsesDefaultKey() bool {
	return len(e.RawKey.Value) == 0 && e.KMSKeyLink.Value == ""
}
