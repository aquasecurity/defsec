package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/digitalocean/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckKubernetesSurgeUpgrades(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Kubernetes cluster surge upgrade disabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:     types.NewTestMetadata(),
						SurgeUpgrade: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Kubernetes cluster surge upgrade enabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:     types.NewTestMetadata(),
						SurgeUpgrade: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.DigitalOcean.Compute = test.input
			results := CheckKubernetesSurgeUpgrades.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckKubernetesSurgeUpgrades.Rule().LongID() {
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
