package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Firewall egress rule with multiple public destination addresses",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Networks: []compute.Network{
					{
						Metadata: types.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: types.NewTestMetadata(),
							EgressRules: []compute.EgressRule{
								{
									Metadata: types.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: types.NewTestMetadata(),
										IsAllow:  types.Bool(true, types.NewTestMetadata()),
										Enforced: types.Bool(true, types.NewTestMetadata()),
									},
									DestinationRanges: []types.StringValue{
										types.String("0.0.0.0/0", types.NewTestMetadata()),
										types.String("1.2.3.4/32", types.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall egress rule with public destination address",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Networks: []compute.Network{
					{
						Metadata: types.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: types.NewTestMetadata(),
							EgressRules: []compute.EgressRule{
								{
									Metadata: types.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: types.NewTestMetadata(),
										IsAllow:  types.Bool(true, types.NewTestMetadata()),
										Enforced: types.Bool(true, types.NewTestMetadata()),
									},
									DestinationRanges: []types.StringValue{
										types.String("1.2.3.4/32", types.NewTestMetadata()),
									},
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
			testState.Google.Compute = test.input
			results := CheckNoPublicEgress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPublicEgress.Rule().LongID() {
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
