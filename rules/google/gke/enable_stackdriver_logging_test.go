package gke

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/gke"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStackdriverLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster missing logging service provider",
			input: gke.GKE{
				Metadata: types.NewTestMetadata(),
				Clusters: []gke.Cluster{
					{
						Metadata:       types.NewTestMetadata(),
						LoggingService: types.String("", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster with StackDriver logging configured",
			input: gke.GKE{
				Metadata: types.NewTestMetadata(),
				Clusters: []gke.Cluster{
					{
						Metadata:       types.NewTestMetadata(),
						LoggingService: types.String("logging.googleapis.com/kubernetes", types.NewTestMetadata()),
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
			results := CheckEnableStackdriverLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableStackdriverLogging.Rule().LongID() {
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
