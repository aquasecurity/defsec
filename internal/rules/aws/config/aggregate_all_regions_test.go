package config

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					Metadata:         types2.NewTestMetadata(),
					SourceAllRegions: types2.Bool(false, types2.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "AWS Config aggregator source with all regions set to true",
			input: config.Config{
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					Metadata:         types2.NewTestMetadata(),
					SourceAllRegions: types2.Bool(true, types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAggregateAllRegions.Rule().LongID() {
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
