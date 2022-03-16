package network

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/network"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckDisableRdpFromInternet(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Security group inbound rule allowing RDP access from the Internet",
			input: network.Network{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: types.NewTestMetadata(),
								Allow:    types.Bool(true, types.NewTestMetadata()),
								Outbound: types.Bool(false, types.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: types.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								SourceAddresses: []types.StringValue{
									types.String("*", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group inbound rule allowing RDP access from a specific address",
			input: network.Network{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: types.NewTestMetadata(),
								Allow:    types.Bool(true, types.NewTestMetadata()),
								Outbound: types.Bool(false, types.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: types.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								SourceAddresses: []types.StringValue{
									types.String("4.53.160.75", types.NewTestMetadata()),
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
			results := CheckDisableRdpFromInternet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckDisableRdpFromInternet.Rule().LongID() {
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
