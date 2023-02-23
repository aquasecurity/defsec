package efs

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	Metadata  defsecTypes.Metadata
	Encrypted defsecTypes.BoolValue
	KmsKeyId  defsecTypes.StringValue
}
