package cloudtrail

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) cloudtrail.CloudTrail {
	return cloudtrail.CloudTrail{
		Trails: getCloudTrails(cfFile),
	}
}
