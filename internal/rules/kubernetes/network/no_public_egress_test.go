package network

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    []kubernetes.NetworkPolicy
		expected bool
	}{
		{
			name: "Public destination CIDR",
			input: []kubernetes.NetworkPolicy{
				{
					Metadata: types.NewTestMetadata(),
					Spec: kubernetes.Spec{
						Metadata: types.NewTestMetadata(),
						Egress: kubernetes.Egress{
							Metadata: types.NewTestMetadata(),
							DestinationCIDRs: []types.StringValue{
								types.String("0.0.0.0/0", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Private destination CIDR",
			input: []kubernetes.NetworkPolicy{
				{
					Metadata: types.NewTestMetadata(),
					Spec: kubernetes.Spec{
						Metadata: types.NewTestMetadata(),
						Egress: kubernetes.Egress{
							Metadata: types.NewTestMetadata(),
							DestinationCIDRs: []types.StringValue{
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
			results := CheckNoPublicEgress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicEgress.Rule().LongID() {
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
