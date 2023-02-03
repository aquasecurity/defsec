package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"
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
			name: "Firewall ingress rule with multiple public source addresses",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: defsecTypes.NewTestMetadata(),
							IngressRules: []compute.IngressRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: defsecTypes.NewTestMetadata(),
										IsAllow:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
										Enforced: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
									},
									SourceRanges: []defsecTypes.StringValue{
										defsecTypes.String("0.0.0.0/0", defsecTypes.NewTestMetadata()),
										defsecTypes.String("1.2.3.4/32", defsecTypes.NewTestMetadata()),
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
			name: "Firewall ingress rule with public source address",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: defsecTypes.NewTestMetadata(),
							IngressRules: []compute.IngressRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: defsecTypes.NewTestMetadata(),
										IsAllow:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
										Enforced: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
									},
									SourceRanges: []defsecTypes.StringValue{
										defsecTypes.String("1.2.3.4/32", defsecTypes.NewTestMetadata()),
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
