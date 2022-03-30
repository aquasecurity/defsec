package gke

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnablePrivateCluster(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster private nodes disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						PrivateCluster: gke.PrivateCluster{
							Metadata:           types.NewTestMetadata(),
							EnablePrivateNodes: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster private nodes enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						PrivateCluster: gke.PrivateCluster{
							Metadata:           types.NewTestMetadata(),
							EnablePrivateNodes: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckEnablePrivateCluster.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnablePrivateCluster.Rule().LongID() {
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
