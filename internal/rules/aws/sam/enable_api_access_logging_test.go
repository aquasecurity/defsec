package sam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableApiAccessLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "API logging not configured",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: types2.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              types2.NewTestMetadata(),
							CloudwatchLogGroupARN: types2.String("", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API logging configured",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: types2.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              types2.NewTestMetadata(),
							CloudwatchLogGroupARN: types2.String("log-group-arn", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SAM = test.input
			results := CheckEnableApiAccessLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableApiAccessLogging.Rule().LongID() {
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
