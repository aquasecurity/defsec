package cloudtrail

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getCloudTrails(ctx parser.FileContext) (trails []cloudtrail.Trail) {

	cloudtrailResources := ctx.GetResourcesByType("AWS::CloudTrail::Trail")

	for _, r := range cloudtrailResources {
		ct := cloudtrail.Trail{
			Metadata:                   r.Metadata(),
			Name:                       r.GetStringProperty("TrailName"),
			Arn:                        r.GetStringProperty("Arn"),
			EnableLogFileValidation:    r.GetBoolProperty("EnableLogFileValidation"),
			IsMultiRegion:              r.GetBoolProperty("IsMultiRegionTrail"),
			KMSKeyID:                   r.GetStringProperty("KmsKeyId"),
			CloudWatchLogsLogGroupArn:  r.GetStringProperty("CloudWatchLogsLogGroupArn"),
			IsLogging:                  r.GetBoolProperty("IsLogging"),
			BucketName:                 r.GetStringProperty("S3BucketName"),
			SnsTopicName:               r.GetStringProperty("SnsTopicName"),
			LatestDeliveryError:        types.StringDefault("", r.Metadata()),
			EventSelectors:             getEventSelectors(r, ctx),
			Tags:                       gettags(r),
			IncludeGlobalServiceEvents: r.GetBoolProperty("IncludeGlobalServiceEvents"),
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
				DataResources:           getdataresources(r),
				IncludeManagementEvents: r.GetBoolProperty("IncludeManagementEvents", true),
			}
			eventselectors = append(eventselectors, eventselector)
		}
	}
	return eventselectors
}

func getdataresources(r *parser.Resource) []cloudtrail.DataResource {
	var dataRes []cloudtrail.DataResource
	Res := r.GetProperty("DataResources")
	if Res.IsNotInt() {
		for _, r := range Res.AsList() {
			var values []types.StringValue
			for _, v := range r.GetProperty("Values").AsList() {
				values = append(values, v.AsStringValue())
			}
			dataRes = append(dataRes, cloudtrail.DataResource{
				Metadata: r.Metadata(),
				Type:     r.GetStringProperty("Type"),
				Values:   values,
			})
		}
	}
	return dataRes
}

func gettags(r *parser.Resource) []cloudtrail.Tags {
	var tags []cloudtrail.Tags
	tagprop := r.GetProperty("Tags")

	if tagprop.IsNil() || tagprop.IsNotNil() {
		return tags
	}

	for _, t := range tagprop.AsList() {
		tags = append(tags, cloudtrail.Tags{
			Metadata: t.Metadata(),
		})
	}
	return tags
}
