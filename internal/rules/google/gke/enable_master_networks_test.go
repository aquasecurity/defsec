package gke

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableMasterNetworks(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster master authorized networks disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types2.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(false, types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster master authorized networks enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types2.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(true, types2.NewTestMetadata()),
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
			results := CheckEnableMasterNetworks.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableMasterNetworks.Rule().LongID() {
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
