package eks

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

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
				Clusters: []eks.Cluster{
					{
						Metadata: types2.NewTestMetadata(),
						Logging: eks.Logging{
							API:               types2.Bool(false, types2.NewTestMetadata()),
							Audit:             types2.Bool(false, types2.NewTestMetadata()),
							Authenticator:     types2.Bool(false, types2.NewTestMetadata()),
							ControllerManager: types2.Bool(false, types2.NewTestMetadata()),
							Scheduler:         types2.Bool(false, types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS cluster with only some cluster logging enabled",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: types2.NewTestMetadata(),
						Logging: eks.Logging{
							API:               types2.Bool(false, types2.NewTestMetadata()),
							Audit:             types2.Bool(true, types2.NewTestMetadata()),
							Authenticator:     types2.Bool(false, types2.NewTestMetadata()),
							ControllerManager: types2.Bool(true, types2.NewTestMetadata()),
							Scheduler:         types2.Bool(true, types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS cluster with all cluster logging enabled",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: types2.NewTestMetadata(),
						Logging: eks.Logging{
							API:               types2.Bool(true, types2.NewTestMetadata()),
							Audit:             types2.Bool(true, types2.NewTestMetadata()),
							Authenticator:     types2.Bool(true, types2.NewTestMetadata()),
							ControllerManager: types2.Bool(true, types2.NewTestMetadata()),
							Scheduler:         types2.Bool(true, types2.NewTestMetadata()),
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
