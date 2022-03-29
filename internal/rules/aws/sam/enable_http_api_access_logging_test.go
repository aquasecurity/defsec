package sam

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableHttpApiAccessLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "HTTP API logging not configured",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				HttpAPIs: []sam.HttpAPI{
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
			name: "HTTP API logging configured",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				HttpAPIs: []sam.HttpAPI{
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
			results := CheckEnableHttpApiAccessLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableHttpApiAccessLogging.Rule().LongID() {
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
