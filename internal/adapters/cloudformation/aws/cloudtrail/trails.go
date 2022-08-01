package cloudtrail

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getCloudTrails(ctx parser.FileContext) (trails []cloudtrail.Trail) {

	cloudtrailResources := ctx.GetResourcesByType("AWS::CloudTrail::Trail")

	for _, r := range cloudtrailResources {
		ct := cloudtrail.Trail{
			Metadata:                r.Metadata(),
			Name:                    r.GetStringProperty("TrailName"),
			EnableLogFileValidation: r.GetBoolProperty("EnableLogFileValidation"),
			IsMultiRegion:           r.GetBoolProperty("IsMultiRegionTrail"),
			KMSKeyID:                r.GetStringProperty("KmsKeyId"),
			BucketName:              r.GetStringProperty("S3BucketName"),
		}

		trails = append(trails, ct)
	}
	return trails
}
