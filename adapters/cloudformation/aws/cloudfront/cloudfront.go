package cloudfront

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result cloudfront.Cloudfront) {

	result.Distributions = getDistributions(cfFile)
	return result

}
