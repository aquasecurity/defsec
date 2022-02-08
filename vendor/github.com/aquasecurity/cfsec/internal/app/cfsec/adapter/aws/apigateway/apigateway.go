package apigateway

import (
	"reflect"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (gateway apigateway.APIGateway) {
	defer func() {
		if r := recover(); r != nil {
			metadata := cfFile.Metadata()
			debug.Log("There were errors adapting %s from %s", reflect.TypeOf(gateway), metadata.Range().GetFilename())
		}
	}()

	gateway.APIs = getApis(cfFile)
	return gateway
}
