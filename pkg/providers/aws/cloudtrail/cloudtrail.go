package cloudtrail

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
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
	defsecTypes.Metadata
	Name                      defsecTypes.StringValue
	EnableLogFileValidation   defsecTypes.BoolValue
	IsMultiRegion             defsecTypes.BoolValue
	KMSKeyID                  defsecTypes.StringValue
	CloudWatchLogsLogGroupArn defsecTypes.StringValue
	IsLogging                 defsecTypes.BoolValue
	BucketName                defsecTypes.StringValue
}
