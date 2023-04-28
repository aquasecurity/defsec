package finspace

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/finspace"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) finspace.ListEnvironements {
	return finspace.ListEnvironements{
		Environments: getListEnvironment(cfFile),
	}
}
