package eks

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableControlPlaneLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    eks.EKS
		expected bool
	}{
		{
			name: "EKS cluster with all cluster logging disabled",
			input: eks.EKS{
				Metadata: types.NewTestMetadata(),
				Clusters: []eks.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Logging: eks.Logging{
							API:               types.Bool(false, types.NewTestMetadata()),
							Audit:             types.Bool(false, types.NewTestMetadata()),
							Authenticator:     types.Bool(false, types.NewTestMetadata()),
							ControllerManager: types.Bool(false, types.NewTestMetadata()),
							Scheduler:         types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS cluster with only some cluster logging enabled",
			input: eks.EKS{
				Metadata: types.NewTestMetadata(),
				Clusters: []eks.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Logging: eks.Logging{
							API:               types.Bool(false, types.NewTestMetadata()),
							Audit:             types.Bool(true, types.NewTestMetadata()),
							Authenticator:     types.Bool(false, types.NewTestMetadata()),
							ControllerManager: types.Bool(true, types.NewTestMetadata()),
							Scheduler:         types.Bool(true, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS cluster with all cluster logging enabled",
			input: eks.EKS{
				Metadata: types.NewTestMetadata(),
				Clusters: []eks.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Logging: eks.Logging{
							API:               types.Bool(true, types.NewTestMetadata()),
							Audit:             types.Bool(true, types.NewTestMetadata()),
							Authenticator:     types.Bool(true, types.NewTestMetadata()),
							ControllerManager: types.Bool(true, types.NewTestMetadata()),
							Scheduler:         types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.EKS = test.input
			results := CheckEnableControlPlaneLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableControlPlaneLogging.Rule().LongID() {
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
