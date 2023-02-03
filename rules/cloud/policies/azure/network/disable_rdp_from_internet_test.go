package network

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

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
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Outbound: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
								Allow:    defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
								SourceAddresses: []defsecTypes.StringValue{
									defsecTypes.String("*", defsecTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								Protocol: defsecTypes.String("Tcp", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Allow:    defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
								Outbound: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								SourceAddresses: []defsecTypes.StringValue{
									defsecTypes.String("4.53.160.75", defsecTypes.NewTestMetadata()),
								},
								Protocol: defsecTypes.String("Tcp", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Outbound: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
								Allow:    defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
								SourceAddresses: []defsecTypes.StringValue{
									defsecTypes.String("*", defsecTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Start:    3310,
										End:      3390,
									},
								},
								Protocol: defsecTypes.String("Icmp", defsecTypes.NewTestMetadata()),
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
