package cloudwatch

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckRequireUnauthorisedApiCallAlarm(t *testing.T) {
	tests := []struct {
		name       string
		cloudtrail cloudtrail.CloudTrail
		cloudwatch cloudwatch.CloudWatch
		expected   bool
	}{
		{
			name: "Multi-region CloudTrail alarms on Unauthorized API calls",
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  types2.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: types2.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", types2.NewTestMetadata()),
						IsLogging:                 types2.Bool(true, types2.NewTestMetadata()),
						IsMultiRegion:             types2.Bool(true, types2.NewTestMetadata()),
					},
				},
			},
			cloudwatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: types2.NewTestMetadata(),
						Arn:      types2.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", types2.NewTestMetadata()),
						MetricFilters: []cloudwatch.MetricFilter{
							{
								Metadata:      types2.NewTestMetadata(),
								FilterName:    types2.String("UnauthorizedAPIUsage", types2.NewTestMetadata()),
								FilterPattern: types2.String(`($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")`, types2.NewTestMetadata()),
							},
						},
					},
				},
				Alarms: []cloudwatch.Alarm{
					{
						Metadata:   types2.NewTestMetadata(),
						AlarmName:  types2.String("CloudTrail_Unauthorized_API_Call", types2.NewTestMetadata()),
						MetricName: types2.String("UnauthorizedAPIUsage", types2.NewTestMetadata()),
						Metrics: []cloudwatch.MetricDataQuery{
							{
								Metadata: types2.NewTestMetadata(),
								ID:       types2.String("UnauthorizedAPIUsage", types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for Unauthorized API calls",
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  types2.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: types2.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", types2.NewTestMetadata()),
						IsLogging:                 types2.Bool(true, types2.NewTestMetadata()),
						IsMultiRegion:             types2.Bool(true, types2.NewTestMetadata()),
					},
				},
			},
			cloudwatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata:      types2.NewTestMetadata(),
						Arn:           types2.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", types2.NewTestMetadata()),
						MetricFilters: []cloudwatch.MetricFilter{},
					},
				},
				Alarms: []cloudwatch.Alarm{
					{
						Metadata:  types2.NewTestMetadata(),
						AlarmName: types2.String("CloudTrail_Unauthorized_API_Call", types2.NewTestMetadata()),
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
			results := requireUnauthorizedApiCallAlarm.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == requireUnauthorizedApiCallAlarm.Rule().LongID() {
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
