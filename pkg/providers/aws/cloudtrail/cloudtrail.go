package cloudtrail

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type CloudTrail struct {
	Trails []Trail
}

func (c CloudTrail) MultiRegionTrails() (multiRegionTrails []Trail) {
	for _, trail := range c.Trails {
		if trail.IsMultiRegion.IsTrue() {
			multiRegionTrails = append(multiRegionTrails, trail)
		}
	}
	return multiRegionTrails
}

type Trail struct {
	types2.Metadata
	Name                      types2.StringValue
	EnableLogFileValidation   types2.BoolValue
	IsMultiRegion             types2.BoolValue
	KMSKeyID                  types2.StringValue
	CloudWatchLogsLogGroupArn types2.StringValue
	IsLogging                 types2.BoolValue
	BucketName                types2.StringValue
}
