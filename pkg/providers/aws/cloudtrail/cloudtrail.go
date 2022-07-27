package cloudtrail

import (
	"github.com/aquasecurity/defsec/internal/types"
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
	types.Metadata
	Name                      types.StringValue
	EnableLogFileValidation   types.BoolValue
	IsMultiRegion             types.BoolValue
	KMSKeyID                  types.StringValue
	CloudWatchLogsLogGroupArn types.StringValue
	IsLogging                 types.BoolValue
}
