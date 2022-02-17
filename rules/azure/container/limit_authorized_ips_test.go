package container

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/container"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
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
				Metadata: types.NewTestMetadata(),
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:                    types.NewTestMetadata(),
						EnablePrivateCluster:        types.Bool(false, types.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []types.StringValue{},
					},
				},
			},
			expected: true,
		},
		{
			name: "API server authorized IP ranges defined",
			input: container.Container{
				Metadata: types.NewTestMetadata(),
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:             types.NewTestMetadata(),
						EnablePrivateCluster: types.Bool(false, types.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []types.StringValue{
							types.String("1.2.3.4/32", types.NewTestMetadata()),
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
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckLimitAuthorizedIps.Rule().LongID() {
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
