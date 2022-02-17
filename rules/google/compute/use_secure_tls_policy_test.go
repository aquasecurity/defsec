package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "SSL policy minimum TLS version 1.0",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				SSLPolicies: []compute.SSLPolicy{
					{
						Metadata:          types.NewTestMetadata(),
						MinimumTLSVersion: types.String("TLS_1_0", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "SSL policy minimum TLS version 1.2",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				SSLPolicies: []compute.SSLPolicy{
					{
						Metadata:          types.NewTestMetadata(),
						MinimumTLSVersion: types.String("TLS_1_2", types.NewTestMetadata()),
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
			results := CheckUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckUseSecureTlsPolicy.Rule().LongID() {
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
