package kendra

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/kendra"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) kendra.Kendra {
	return kendra.Kendra{
		ListIndices: getListIndices(cfFile),
	}
}
