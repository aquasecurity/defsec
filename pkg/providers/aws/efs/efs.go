package efs

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type EFS struct {
	types.Metadata
	FileSystems []FileSystem
}

type FileSystem struct {
	types.Metadata
	Encrypted types.BoolValue
}
