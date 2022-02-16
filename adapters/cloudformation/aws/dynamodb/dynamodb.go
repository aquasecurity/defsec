package dynamodb

import (
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result dynamodb.DynamoDB) {

	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.DAXClusters = getClusters(cfFile)
	return result

}
