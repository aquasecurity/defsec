package network

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/network"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: types2.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: types2.NewTestMetadata(),
								Outbound: types2.Bool(false, types2.NewTestMetadata()),
								Allow:    types2.Bool(true, types2.NewTestMetadata()),
								SourceAddresses: []types2.StringValue{
									types2.String("*", types2.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: types2.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								Protocol: types2.String("Tcp", types2.NewTestMetadata()),
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
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: types2.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: types2.NewTestMetadata(),
								Allow:    types2.Bool(true, types2.NewTestMetadata()),
								Outbound: types2.Bool(false, types2.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: types2.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								SourceAddresses: []types2.StringValue{
									types2.String("4.53.160.75", types2.NewTestMetadata()),
								},
								Protocol: types2.String("Tcp", types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group inbound rule allowing only ICMP",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: types2.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: types2.NewTestMetadata(),
								Outbound: types2.Bool(false, types2.NewTestMetadata()),
								Allow:    types2.Bool(true, types2.NewTestMetadata()),
								SourceAddresses: []types2.StringValue{
									types2.String("*", types2.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: types2.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								Protocol: types2.String("Icmp", types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDisableRdpFromInternet.Rule().LongID() {
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
