package efs

import "github.com/aquasecurity/defsec/types"

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	*types.Metadata
	Encrypted types.BoolValue
}
