package efs

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	defsecTypes.Metadata
	Encrypted defsecTypes.BoolValue
}
