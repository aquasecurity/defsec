package network

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/network"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Security group outbound rule with wildcard destination address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: types2.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: types2.NewTestMetadata(),
								Allow:    types2.Bool(true, types2.NewTestMetadata()),
								Outbound: types2.Bool(true, types2.NewTestMetadata()),
								DestinationAddresses: []types2.StringValue{
									types2.String("*", types2.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group outbound rule with private destination address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: types2.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: types2.NewTestMetadata(),
								Allow:    types2.Bool(true, types2.NewTestMetadata()),
								Outbound: types2.Bool(true, types2.NewTestMetadata()),
								DestinationAddresses: []types2.StringValue{
									types2.String("10.0.0.0/16", types2.NewTestMetadata()),
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
			testState.Azure.Network = test.input
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
