package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/digitalocean/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckAutoUpgrade(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Kubernetes cluster auto-upgrade disabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:    types.NewTestMetadata(),
						AutoUpgrade: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Kubernetes cluster auto-upgrade enabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:    types.NewTestMetadata(),
						AutoUpgrade: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckAutoUpgrade.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckAutoUpgrade.Rule().LongID() {
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
