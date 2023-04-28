package fsx

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/fsx"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) fsx.Fsx {
	return fsx.Fsx{
		Filesystems: getFileSystem(cfFile),
	}
}
