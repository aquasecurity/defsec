package cloudformation

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudformation"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) cloudformation.Cloudformation {
	return cloudformation.Cloudformation{
		Stacks: getStacks(cfFile),
	}
}
