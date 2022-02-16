package cloudtrail

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudtrail"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result cloudtrail.CloudTrail) {

	result.Trails = getCloudTrails(cfFile)
	return result
}
