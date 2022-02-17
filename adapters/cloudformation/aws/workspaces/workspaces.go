package workspaces

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result workspaces.WorkSpaces) {

	result.WorkSpaces = getWorkSpaces(cfFile)
	return result
}
