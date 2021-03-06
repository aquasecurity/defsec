package rds

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicDbAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "RDS Instance with public access enabled",
			input: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:     types.NewTestMetadata(),
						PublicAccess: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Instance with public access disabled",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Instances: []rds.ClusterInstance{
							{
								Metadata: types.NewTestMetadata(),
								Instance: rds.Instance{
									Metadata:     types.NewTestMetadata(),
									PublicAccess: types.Bool(false, types.NewTestMetadata()),
								},
							},
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
			results := CheckNoPublicDbAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicDbAccess.Rule().LongID() {
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
