package cloudfront

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result cloudfront.Cloudfront) {

	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.Distributions = getDistributions(cfFile)
	return result

}
