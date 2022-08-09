package efs

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	types2.Metadata
	Encrypted types2.BoolValue
}
