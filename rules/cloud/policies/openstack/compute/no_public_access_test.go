package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/openstack"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    openstack.Compute
		expected bool
	}{
		{
			name: "Firewall rule missing destination address",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    defsecTypes.NewTestMetadata(),
							Enabled:     defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Destination: defsecTypes.String("", defsecTypes.NewTestMetadata()),
							Source:      defsecTypes.String("10.10.10.1", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule missing source address",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    defsecTypes.NewTestMetadata(),
							Enabled:     defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Destination: defsecTypes.String("10.10.10.2", defsecTypes.NewTestMetadata()),
							Source:      defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule with public destination and source addresses",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    defsecTypes.NewTestMetadata(),
							Enabled:     defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Destination: defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
							Source:      defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule with private destination and source addresses",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    defsecTypes.NewTestMetadata(),
							Enabled:     defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Destination: defsecTypes.String("10.10.10.1", defsecTypes.NewTestMetadata()),
							Source:      defsecTypes.String("10.10.10.2", defsecTypes.NewTestMetadata()),
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
			testState.OpenStack.Compute = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
