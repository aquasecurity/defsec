package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoDefaultServiceAccount(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Instance service account missing email",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Instances: []compute.Instance{
					{
						Metadata: types.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata: types.NewTestMetadata(),
							Email:    types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance service account using the default email",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Instances: []compute.Instance{
					{
						Metadata: types.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata: types.NewTestMetadata(),
							Email:    types.String("1234567890-compute@developer.gserviceaccount.com", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance service account with email provided",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Instances: []compute.Instance{
					{
						Metadata: types.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata: types.NewTestMetadata(),
							Email:    types.String("proper@email.com", types.NewTestMetadata()),
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
			testState.Google.Compute = test.input
			results := CheckNoDefaultServiceAccount.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoDefaultServiceAccount.Rule().LongID() {
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
