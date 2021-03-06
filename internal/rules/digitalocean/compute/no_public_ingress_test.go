package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/digitalocean/compute"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Firewall inbound rule with multiple public source addresses",
			input: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: types.NewTestMetadata(),
						InboundRules: []compute.InboundFirewallRule{
							{
								Metadata: types.NewTestMetadata(),
								SourceAddresses: []types.StringValue{
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
			name: "Firewall inbound rule with a private source address",
			input: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: types.NewTestMetadata(),
						InboundRules: []compute.InboundFirewallRule{
							{
								Metadata: types.NewTestMetadata(),
								SourceAddresses: []types.StringValue{
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
			results := CheckNoPublicIngress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngress.Rule().LongID() {
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
