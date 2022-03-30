package container

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/container"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckConfiguredNetworkPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name: "Cluster missing network policy configuration",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: types.NewTestMetadata(),
						NetworkProfile: container.NetworkProfile{
							Metadata:      types.NewTestMetadata(),
							NetworkPolicy: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster with network policy configured",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: types.NewTestMetadata(),
						NetworkProfile: container.NetworkProfile{
							Metadata:      types.NewTestMetadata(),
							NetworkPolicy: types.String("calico", types.NewTestMetadata()),
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
			results := CheckConfiguredNetworkPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckConfiguredNetworkPolicy.Rule().LongID() {
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
