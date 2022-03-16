package monitor

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/monitor"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckCaptureAllActivities(t *testing.T) {
	tests := []struct {
		name     string
		input    monitor.Monitor
		expected bool
	}{
		{
			name: "Log profile captures only write activities",
			input: monitor.Monitor{
				Metadata: types.NewTestMetadata(),
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: types.NewTestMetadata(),
						Categories: []types.StringValue{
							types.String("Write", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log profile captures action, write, delete activities",
			input: monitor.Monitor{
				Metadata: types.NewTestMetadata(),
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: types.NewTestMetadata(),
						Categories: []types.StringValue{
							types.String("Action", types.NewTestMetadata()),
							types.String("Write", types.NewTestMetadata()),
							types.String("Delete", types.NewTestMetadata()),
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
			testState.Azure.Monitor = test.input
			results := CheckCaptureAllActivities.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckCaptureAllActivities.Rule().LongID() {
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
