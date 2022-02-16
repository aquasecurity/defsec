package athena

import (
	"github.com/aquasecurity/defsec/provider/aws/athena"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result athena.Athena) {

	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.Workgroups = getWorkGroups(cfFile)
	return result
}
