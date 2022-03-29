package rds

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnablePerformanceInsights(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "RDS Instance with performance insights disabled",
			input: rds.RDS{
				Metadata: types.NewTestMetadata(),
				Instances: []rds.Instance{
					{
						Metadata: types.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(false, types.NewTestMetadata()),
							KMSKeyID: types.String("some-kms-key", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},

		{
			name: "RDS Instance with performance insights enabled and KMS key provided",
			input: rds.RDS{
				Metadata: types.NewTestMetadata(),
				Instances: []rds.Instance{
					{
						Metadata: types.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
							KMSKeyID: types.String("some-kms-key", types.NewTestMetadata()),
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
			testState.AWS.RDS = test.input
			results := CheckEnablePerformanceInsights.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnablePerformanceInsights.Rule().LongID() {
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
