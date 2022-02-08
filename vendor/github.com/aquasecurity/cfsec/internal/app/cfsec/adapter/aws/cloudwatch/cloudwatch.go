package cloudwatch

import (
	"reflect"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/cloudwatch"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result cloudwatch.CloudWatch) {


	defer func() {
		if r := recover(); r != nil {
			metadata := cfFile.Metadata()
			debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.LogGroups = getLogGroups(cfFile)
	return result

}
