package workspaces

import (
	"reflect"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result workspaces.WorkSpaces) {
	defer func() {
		if r := recover(); r != nil {
			metadata := cfFile.Metadata()
			debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.WorkSpaces = getWorkSpaces(cfFile)
	return result
}
