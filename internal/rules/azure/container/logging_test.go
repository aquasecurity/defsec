package container

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/container"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name: "Logging via OMS agent disabled",
			input: container.Container{
				Metadata: types.NewTestMetadata(),
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: types.NewTestMetadata(),
						AddonProfile: container.AddonProfile{
							Metadata: types.NewTestMetadata(),
							OMSAgent: container.OMSAgent{
								Metadata: types.NewTestMetadata(),
								Enabled:  types.Bool(false, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Logging via OMS agent enabled",
			input: container.Container{
				Metadata: types.NewTestMetadata(),
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: types.NewTestMetadata(),
						AddonProfile: container.AddonProfile{
							Metadata: types.NewTestMetadata(),
							OMSAgent: container.OMSAgent{
								Metadata: types.NewTestMetadata(),
								Enabled:  types.Bool(true, types.NewTestMetadata()),
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
			testState.Azure.Container = test.input
			results := CheckLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLogging.Rule().LongID() {
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
