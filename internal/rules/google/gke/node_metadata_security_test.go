package gke

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNodeMetadataSecurity(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster node pools metadata exposed by default",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: types.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     types.NewTestMetadata(),
								NodeMetadata: types.String("UNSPECIFIED", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Node pool metadata exposed",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: types.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     types.NewTestMetadata(),
								NodeMetadata: types.String("SECURE", types.NewTestMetadata()),
							},
						},
						NodePools: []gke.NodePool{
							{
								Metadata: types.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									Metadata: types.NewTestMetadata(),
									WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
										Metadata:     types.NewTestMetadata(),
										NodeMetadata: types.String("EXPOSE", types.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node pools metadata secured",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: types.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     types.NewTestMetadata(),
								NodeMetadata: types.String("SECURE", types.NewTestMetadata()),
							},
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
			results := CheckNodeMetadataSecurity.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNodeMetadataSecurity.Rule().LongID() {
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
