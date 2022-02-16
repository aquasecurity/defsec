package workspaces

import (
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result workspaces.WorkSpaces) {

	result.WorkSpaces = getWorkSpaces(cfFile)
	return result
}
