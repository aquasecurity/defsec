package gke

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforcePodSecurityPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster pod security policy disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						PodSecurityPolicy: gke.PodSecurityPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster pod security policy enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						PodSecurityPolicy: gke.PodSecurityPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			results := CheckEnforcePodSecurityPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforcePodSecurityPolicy.Rule().LongID() {
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
