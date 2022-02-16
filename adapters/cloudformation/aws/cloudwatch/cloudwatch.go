package cloudwatch

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudwatch"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result cloudwatch.CloudWatch) {

	result.LogGroups = getLogGroups(cfFile)
	return result

}
