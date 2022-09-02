package cloudwatch

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckRequireOrgChangesAlarm(t *testing.T) {
	tests := []struct {
		name       string
		cloudwatch cloudwatch.CloudWatch
		expected   bool
	}{
		{
			name: "alarm exists",
			cloudwatch: cloudwatch.CloudWatch{
				Alarms: []cloudwatch.Alarm{
					{
						Metadata:   defsecTypes.NewTestMetadata(),
						MetricName: defsecTypes.String("OrganizationEvents", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name:       "alarm does not exist",
			cloudwatch: cloudwatch.CloudWatch{},
			expected:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudWatch = test.cloudwatch
			results := CheckRequireOrgChangesAlarm.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireOrgChangesAlarm.Rule().LongID() {
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
