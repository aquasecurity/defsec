package cloudtrail

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/cloudtrail"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result cloudtrail.CloudTrail) {

	result.Trails = getCloudTrails(cfFile)
	return result
}
