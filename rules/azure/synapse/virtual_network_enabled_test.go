package synapse

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/synapse"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckVirtualNetworkEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    synapse.Synapse
		expected bool
	}{
		{
			name: "Synapse workspace managed VN disabled",
			input: synapse.Synapse{
				Metadata: types.NewTestMetadata(),
				Workspaces: []synapse.Workspace{
					{
						Metadata:                    types.NewTestMetadata(),
						EnableManagedVirtualNetwork: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Synapse workspace managed VN enabled",
			input: synapse.Synapse{
				Metadata: types.NewTestMetadata(),
				Workspaces: []synapse.Workspace{
					{
						Metadata:                    types.NewTestMetadata(),
						EnableManagedVirtualNetwork: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.Synapse = test.input
			results := CheckVirtualNetworkEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckVirtualNetworkEnabled.Rule().LongID() {
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
