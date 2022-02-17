package config

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/aws/config"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckAggregateAllRegions(t *testing.T) {
	tests := []struct {
		name     string
		input    config.Config
		expected bool
	}{
		{
			name: "AWS Config aggregator source with all regions set to false",
			input: config.Config{
				Metadata: types.NewTestMetadata(),
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					Metadata:         types.NewTestMetadata(),
					SourceAllRegions: types.Bool(false, types.NewTestMetadata()),
					IsDefined:        true,
				},
			},
			expected: true,
		},
		{
			name: "AWS Config aggregator source with all regions set to true",
			input: config.Config{
				Metadata: types.NewTestMetadata(),
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					Metadata:         types.NewTestMetadata(),
					SourceAllRegions: types.Bool(true, types.NewTestMetadata()),
					IsDefined:        true,
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Config = test.input
			results := CheckAggregateAllRegions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckAggregateAllRegions.Rule().LongID() {
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
