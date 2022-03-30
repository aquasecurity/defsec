package cloudtrail

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableLogValidation(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudtrail.CloudTrail
		expected bool
	}{
		{
			name: "AWS CloudTrail without logfile validation",
			input: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                types.NewTestMetadata(),
						EnableLogFileValidation: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS CloudTrail with logfile validation enabled",
			input: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                types.NewTestMetadata(),
						EnableLogFileValidation: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudTrail = test.input
			results := CheckEnableLogValidation.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableLogValidation.Rule().LongID() {
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
