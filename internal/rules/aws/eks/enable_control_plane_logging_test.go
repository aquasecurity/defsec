package eks

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

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
						Metadata: defsecTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							Audit:             defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							Authenticator:     defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							ControllerManager: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							Scheduler:         defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							Audit:             defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Authenticator:     defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							ControllerManager: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Scheduler:         defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Audit:             defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Authenticator:     defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							ControllerManager: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Scheduler:         defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
