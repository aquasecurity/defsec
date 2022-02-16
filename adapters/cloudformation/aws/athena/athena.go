package athena

import (
	"github.com/aquasecurity/defsec/provider/aws/athena"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result athena.Athena) {
	result.Workgroups = getWorkGroups(cfFile)
	return result
}
