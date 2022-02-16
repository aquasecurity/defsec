package apigateway

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (gateway apigateway.APIGateway) {
	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(gateway), metadata.Range().GetFilename())
		}
	}()

	gateway.APIs = getApis(cfFile)
	return gateway
}
