package gke

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoLegacyAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster master authentication by certificate",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						MasterAuth: gke.MasterAuth{
							Metadata: types.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         types.NewTestMetadata(),
								IssueCertificate: types.Bool(true, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster master authentication by username/password",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						MasterAuth: gke.MasterAuth{
							Metadata: types.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         types.NewTestMetadata(),
								IssueCertificate: types.Bool(false, types.NewTestMetadata()),
							},
							Username: types.String("username", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster master authentication by certificate or username/password disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						MasterAuth: gke.MasterAuth{
							Metadata: types.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         types.NewTestMetadata(),
								IssueCertificate: types.Bool(false, types.NewTestMetadata()),
							},
							Username: types.String("", types.NewTestMetadata()),
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
			results := CheckNoLegacyAuthentication.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoLegacyAuthentication.Rule().LongID() {
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
