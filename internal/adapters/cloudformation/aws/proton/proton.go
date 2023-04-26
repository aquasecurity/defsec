package proton

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/proton"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) proton.Proton {
	return proton.Proton{
		ListEnvironmentTemplates: nil,
	}
}
