package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/digitalocean/compute"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Firewall outbound rule with multiple public destination addresses",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Firewalls: []compute.Firewall{
					{
						Metadata: types.NewTestMetadata(),
						OutboundRules: []compute.OutboundFirewallRule{
							{
								Metadata: types.NewTestMetadata(),
								DestinationAddresses: []types.StringValue{
									types.String("0.0.0.0/0", types.NewTestMetadata()),
									types.String("::/0", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall outbound rule with a private destination address",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Firewalls: []compute.Firewall{
					{
						Metadata: types.NewTestMetadata(),
						OutboundRules: []compute.OutboundFirewallRule{
							{
								Metadata: types.NewTestMetadata(),
								DestinationAddresses: []types.StringValue{
									types.String("192.168.1.0/24", types.NewTestMetadata()),
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
			testState.DigitalOcean.Compute = test.input
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
