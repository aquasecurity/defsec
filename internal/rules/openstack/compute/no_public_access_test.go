package compute

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

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
							Metadata:    types2.NewTestMetadata(),
							Enabled:     types2.Bool(true, types2.NewTestMetadata()),
							Destination: types2.String("", types2.NewTestMetadata()),
							Source:      types2.String("10.10.10.1", types2.NewTestMetadata()),
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
							Metadata:    types2.NewTestMetadata(),
							Enabled:     types2.Bool(true, types2.NewTestMetadata()),
							Destination: types2.String("10.10.10.2", types2.NewTestMetadata()),
							Source:      types2.String("", types2.NewTestMetadata()),
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
							Metadata:    types2.NewTestMetadata(),
							Enabled:     types2.Bool(true, types2.NewTestMetadata()),
							Destination: types2.String("0.0.0.0", types2.NewTestMetadata()),
							Source:      types2.String("0.0.0.0", types2.NewTestMetadata()),
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
							Metadata:    types2.NewTestMetadata(),
							Enabled:     types2.Bool(true, types2.NewTestMetadata()),
							Destination: types2.String("10.10.10.1", types2.NewTestMetadata()),
							Source:      types2.String("10.10.10.2", types2.NewTestMetadata()),
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
