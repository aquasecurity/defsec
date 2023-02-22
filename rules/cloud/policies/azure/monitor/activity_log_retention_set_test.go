package monitor

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/monitor"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckActivityLogRetentionSet(t *testing.T) {
	tests := []struct {
		name     string
		input    monitor.Monitor
		expected bool
	}{
		{
			name: "Log retention policy disabled",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							Days:     defsecTypes.Int(365, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log retention policy enabled for 90 days",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Days:     defsecTypes.Int(90, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log retention policy enabled for 365 days",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Days:     defsecTypes.Int(365, defsecTypes.NewTestMetadata()),
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
			results := CheckActivityLogRetentionSet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckActivityLogRetentionSet.Rule().LongID() {
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
