package athena

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/athena"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result athena.Athena) {
	result.Workgroups = getWorkGroups(cfFile)
	return result
}
