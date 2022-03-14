package container

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/container"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckUseRbacPermissions(t *testing.T) {
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name: "Role based access control disabled",
			input: container.Container{
				Metadata: types.NewTestMetadata(),
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: types.NewTestMetadata(),
						RoleBasedAccessControl: container.RoleBasedAccessControl{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Role based access control enabled",
			input: container.Container{
				Metadata: types.NewTestMetadata(),
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: types.NewTestMetadata(),
						RoleBasedAccessControl: container.RoleBasedAccessControl{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
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
			results := CheckUseRbacPermissions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckUseRbacPermissions.Rule().LongID() {
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
