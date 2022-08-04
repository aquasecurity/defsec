package cloudwatch

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckCMKDisabledAlarm(t *testing.T) {
	tests := []struct {
		name       string
		cloudtrail cloudtrail.CloudTrail
		cloudwatch cloudwatch.CloudWatch
		expected   bool
	}{
		{
			name: "Multi-region CloudTrail alarms on CMK disabled or scheduled deletion",
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  types.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: types.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", types.NewTestMetadata()),
						IsLogging:                 types.Bool(true, types.NewTestMetadata()),
						IsMultiRegion:             types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			cloudwatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: types.NewTestMetadata(),
						Arn:      types.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", types.NewTestMetadata()),
						MetricFilters: []cloudwatch.MetricFilter{
							{
								Metadata:      types.NewTestMetadata(),
								FilterName:    types.String("CMKDisbledOrScheduledDelete", types.NewTestMetadata()),
								FilterPattern: types.String(`{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}`, types.NewTestMetadata()),
							},
						},
					},
				},
				Alarms: []cloudwatch.Alarm{
					{
						Metadata:   types.NewTestMetadata(),
						AlarmName:  types.String("CMKDisbledOrScheduledDelete", types.NewTestMetadata()),
						MetricName: types.String("CMKDisbledOrScheduledDelete", types.NewTestMetadata()),
						Metrics: []cloudwatch.MetricDataQuery{
							{
								Metadata: types.NewTestMetadata(),
								ID:       types.String("CMKDisbledOrScheduledDelete", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for CMK Disabled or scheduled deletion",
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  types.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: types.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", types.NewTestMetadata()),
						IsLogging:                 types.Bool(true, types.NewTestMetadata()),
						IsMultiRegion:             types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			cloudwatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata:      types.NewTestMetadata(),
						Arn:           types.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", types.NewTestMetadata()),
						MetricFilters: []cloudwatch.MetricFilter{},
					},
				},
				Alarms: []cloudwatch.Alarm{
					{
						Metadata:  types.NewTestMetadata(),
						AlarmName: types.String("CMKDisbledOrScheduledDelete", types.NewTestMetadata()),
						Metrics: []cloudwatch.MetricDataQuery{
							{},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudWatch = test.cloudwatch
			testState.AWS.CloudTrail = test.cloudtrail
			results := requireCloudTrailChangeAlarm.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == requireCloudTrailChangeAlarm.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
