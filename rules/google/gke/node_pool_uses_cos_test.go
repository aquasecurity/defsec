package gke

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/google/gke"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNodePoolUsesCos(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster node config image type set to Ubuntu",
			input: gke.GKE{
				Metadata: types.NewTestMetadata(),
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  types.NewTestMetadata(),
							ImageType: types.String("UBUNTU", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node pool image type set to Ubuntu",
			input: gke.GKE{
				Metadata: types.NewTestMetadata(),
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  types.NewTestMetadata(),
							ImageType: types.String("COS", types.NewTestMetadata()),
						},
						NodePools: []gke.NodePool{
							{
								Metadata: types.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									Metadata:  types.NewTestMetadata(),
									ImageType: types.String("UBUNTU", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node config image type set to Container-Optimized OS",
			input: gke.GKE{
				Metadata: types.NewTestMetadata(),
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  types.NewTestMetadata(),
							ImageType: types.String("COS_CONTAINERD", types.NewTestMetadata()),
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
			results := CheckNodePoolUsesCos.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNodePoolUsesCos.Rule().LongID() {
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
