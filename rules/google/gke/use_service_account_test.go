package gke

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/gke"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckUseServiceAccount(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster node config with default service account",
			input: gke.GKE{
				Metadata: types.NewTestMetadata(),
				Clusters: []gke.Cluster{
					{
						Metadata:              types.NewTestMetadata(),
						RemoveDefaultNodePool: types.Bool(false, types.NewTestMetadata()),
						NodeConfig: gke.NodeConfig{
							Metadata:       types.NewTestMetadata(),
							ServiceAccount: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node config with service account provided",
			input: gke.GKE{
				Metadata: types.NewTestMetadata(),
				Clusters: []gke.Cluster{
					{
						Metadata:              types.NewTestMetadata(),
						RemoveDefaultNodePool: types.Bool(false, types.NewTestMetadata()),
						NodeConfig: gke.NodeConfig{
							Metadata:       types.NewTestMetadata(),
							ServiceAccount: types.String("service-account", types.NewTestMetadata()),
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
			testState.Google.GKE = test.input
			results := CheckUseServiceAccount.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckUseServiceAccount.Rule().LongID() {
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
