package cloudwatch

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLogGroupCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudwatch.CloudWatch
		expected bool
	}{
		{
			name: "AWS CloudWatch with unencrypted log group",
			input: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: types2.NewTestMetadata(),
						KMSKeyID: types2.String("", types2.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS CloudWatch with encrypted log group",
			input: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: types2.NewTestMetadata(),
						KMSKeyID: types2.String("some-kms-key", types2.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudWatch = test.input
			results := CheckLogGroupCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLogGroupCustomerKey.Rule().LongID() {
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
