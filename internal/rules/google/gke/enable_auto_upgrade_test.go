package gke

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAutoUpgrade(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Node pool auto upgrade disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: types.NewTestMetadata(),
								Management: gke.Management{
									Metadata:          types.NewTestMetadata(),
									EnableAutoUpgrade: types.Bool(false, types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Node pool auto upgrade enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: types.NewTestMetadata(),
								Management: gke.Management{
									Metadata:          types.NewTestMetadata(),
									EnableAutoUpgrade: types.Bool(true, types.NewTestMetadata()),
								},
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
			results := CheckEnableAutoUpgrade.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAutoUpgrade.Rule().LongID() {
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
