package apigateway

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (gateway apigateway.APIGateway) {
	gateway.APIs = getApis(cfFile)
	return gateway
}
