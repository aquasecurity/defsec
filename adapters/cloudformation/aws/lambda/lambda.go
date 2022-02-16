package lambda

import (
	"github.com/aquasecurity/defsec/provider/aws/lambda"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result lambda.Lambda) {

	result.Functions = getFunctions(cfFile)
	return result

}
