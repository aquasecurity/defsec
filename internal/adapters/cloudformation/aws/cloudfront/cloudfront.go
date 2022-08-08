package cloudfront

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) cloudfront.Cloudfront {
	return cloudfront.Cloudfront{
		Distributions: getDistributions(cfFile),
	}
}
