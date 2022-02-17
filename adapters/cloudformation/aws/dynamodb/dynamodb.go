package dynamodb

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result dynamodb.DynamoDB) {

	result.DAXClusters = getClusters(cfFile)
	return result

}
