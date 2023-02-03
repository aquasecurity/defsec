package gke

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckMetadataEndpointsDisabled(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster legacy metadata endpoints enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              defsecTypes.NewTestMetadata(),
							EnableLegacyEndpoints: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster legacy metadata endpoints disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              defsecTypes.NewTestMetadata(),
							EnableLegacyEndpoints: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "Cluster legacy metadata endpoints disabled on non-default node pool",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              defsecTypes.NewTestMetadata(),
							EnableLegacyEndpoints: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						NodePools: []gke.NodePool{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									EnableLegacyEndpoints: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Cluster legacy metadata endpoints enabled on non-default node pool",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              defsecTypes.NewTestMetadata(),
							EnableLegacyEndpoints: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						NodePools: []gke.NodePool{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									EnableLegacyEndpoints: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.GKE = test.input
			results := CheckMetadataEndpointsDisabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckMetadataEndpointsDisabled.Rule().LongID() {
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
