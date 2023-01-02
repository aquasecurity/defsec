package cloudtrail

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getCloudTrails(ctx parser.FileContext) (trails []cloudtrail.Trail) {

	cloudtrailResources := ctx.GetResourcesByType("AWS::CloudTrail::Trail")

	for _, r := range cloudtrailResources {
		ct := cloudtrail.Trail{
			Metadata:                  r.Metadata(),
			Name:                      r.GetStringProperty("TrailName"),
			EnableLogFileValidation:   r.GetBoolProperty("EnableLogFileValidation"),
			IsMultiRegion:             r.GetBoolProperty("IsMultiRegionTrail"),
			KMSKeyID:                  r.GetStringProperty("KmsKeyId"),
			CloudWatchLogsLogGroupArn: r.GetStringProperty("CloudWatchLogsLogGroupArn"),
			IsLogging:                 r.GetBoolProperty("IsLogging"),
			BucketName:                r.GetStringProperty("S3BucketName"),
			SnsTopicName:              r.GetStringProperty("SnsTopicName"),
			EventSelectors:            getEventSelectors(r, ctx),
		}

		trails = append(trails, ct)
	}
	return trails
}

func getEventSelectors(t *parser.Resource, ctx parser.FileContext) (eventselectors []cloudtrail.EventSelector) {
	eventselectorResources := ctx.GetResourcesByType("AWS::CloudTrail::Trail EventSelector")

	for _, r := range eventselectorResources {
		if r.GetStringProperty("TrailARN").Value() == t.ID() {
			eventselector := cloudtrail.EventSelector{
				Metadata:                r.Metadata(),
				IncludeManagementEvents: r.GetBoolProperty("IncludeManagementEvents", true),
			}
			eventselectors = append(eventselectors, eventselector)
		}
	}
	return eventselectors
}
