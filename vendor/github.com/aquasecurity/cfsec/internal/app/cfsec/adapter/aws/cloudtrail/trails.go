package cloudtrail

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/cloudtrail"
)

func getCloudTrails(ctx parser.FileContext) (trails []cloudtrail.Trail) {

	cloudtrailResources := ctx.GetResourceByType("AWS::CloudTrail::Trail")

	for _, r := range cloudtrailResources {
		ct := cloudtrail.Trail{
			Metadata:          r.Metadata(),
			Name:                    r.GetStringProperty("TrailName"),
			EnableLogFileValidation: r.GetBoolProperty("EnableLogFileValidation"),
			IsMultiRegion:           r.GetBoolProperty("IsMultiRegionTrail"),
			KMSKeyID:                r.GetStringProperty("KmsKeyId"),
		}

		trails = append(trails, ct)
	}
	return trails
}
