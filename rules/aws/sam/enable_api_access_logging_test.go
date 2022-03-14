package sam

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/sam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
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
				Metadata: types.NewTestMetadata(),
				APIs: []sam.API{
					{
						Metadata: types.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              types.NewTestMetadata(),
							CloudwatchLogGroupARN: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API logging configured",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				APIs: []sam.API{
					{
						Metadata: types.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              types.NewTestMetadata(),
							CloudwatchLogGroupARN: types.String("log-group-arn", types.NewTestMetadata()),
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
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckEnableApiAccessLogging.Rule().LongID() {
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
