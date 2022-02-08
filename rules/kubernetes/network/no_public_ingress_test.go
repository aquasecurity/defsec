package network

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/kubernetes"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    []kubernetes.NetworkPolicy
		expected bool
	}{
		{
			name: "Public source CIDR",
			input: []kubernetes.NetworkPolicy{
				{
					Metadata: types.NewTestMetadata(),
					Spec: kubernetes.Spec{
						Metadata: types.NewTestMetadata(),
						Ingress: kubernetes.Ingress{
							Metadata: types.NewTestMetadata(),
							SourceCIDRs: []types.StringValue{
								types.String("0.0.0.0/0", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Private source CIDR",
			input: []kubernetes.NetworkPolicy{
				{
					Metadata: types.NewTestMetadata(),
					Spec: kubernetes.Spec{
						Metadata: types.NewTestMetadata(),
						Ingress: kubernetes.Ingress{
							Metadata: types.NewTestMetadata(),
							SourceCIDRs: []types.StringValue{
								types.String("10.0.0.0/16", types.NewTestMetadata()),
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
			testState.Kubernetes.NetworkPolicies = test.input
			results := CheckNoPublicIngress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPublicIngress.Rule().LongID() {
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
