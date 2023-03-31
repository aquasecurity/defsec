package container

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/container"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLimitAuthorizedIps(t *testing.T) {
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name: "API server authorized IP ranges undefined",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:                    defsecTypes.NewTestMetadata(),
						EnablePrivateCluster:        defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []defsecTypes.StringValue{},
					},
				},
			},
			expected: true,
		},
		{
			name: "API server authorized IP ranges defined",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:             defsecTypes.NewTestMetadata(),
						EnablePrivateCluster: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []defsecTypes.StringValue{
							defsecTypes.String("1.2.3.4/32", defsecTypes.NewTestMetadata()),
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
			results := CheckLimitAuthorizedIps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLimitAuthorizedIps.Rule().LongID() {
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
