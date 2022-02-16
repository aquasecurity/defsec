package dynamodb

import (
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result dynamodb.DynamoDB) {

	result.DAXClusters = getClusters(cfFile)
	return result

}
