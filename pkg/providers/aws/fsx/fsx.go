package fsx

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Fsx struct {
	Filesystems []Filesystem
}

type Filesystem struct {
	Metadata       defsecTypes.Metadata
	FileSystemType defsecTypes.StringValue
	KmsKeyId       defsecTypes.StringValue
}
