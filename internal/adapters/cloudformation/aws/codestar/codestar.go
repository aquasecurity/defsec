package codestar

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codestar"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) codestar.CodeStar {
	return codestar.CodeStar{
		Projects: nil,
	}
}
