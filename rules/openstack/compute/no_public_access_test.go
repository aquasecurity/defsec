package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/openstack"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
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
				Metadata: types.NewTestMetadata(),
				Firewall: openstack.Firewall{
					Metadata: types.NewTestMetadata(),
					AllowRules: []openstack.Rule{
						{
							Metadata:    types.NewTestMetadata(),
							Enabled:     types.Bool(true, types.NewTestMetadata()),
							Destination: types.String("", types.NewTestMetadata()),
							Source:      types.String("10.10.10.1", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule missing source address",
			input: openstack.Compute{
				Metadata: types.NewTestMetadata(),
				Firewall: openstack.Firewall{
					Metadata: types.NewTestMetadata(),
					AllowRules: []openstack.Rule{
						{
							Metadata:    types.NewTestMetadata(),
							Enabled:     types.Bool(true, types.NewTestMetadata()),
							Destination: types.String("10.10.10.2", types.NewTestMetadata()),
							Source:      types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule with public destination and source addresses",
			input: openstack.Compute{
				Metadata: types.NewTestMetadata(),
				Firewall: openstack.Firewall{
					Metadata: types.NewTestMetadata(),
					AllowRules: []openstack.Rule{
						{
							Metadata:    types.NewTestMetadata(),
							Enabled:     types.Bool(true, types.NewTestMetadata()),
							Destination: types.String("0.0.0.0", types.NewTestMetadata()),
							Source:      types.String("0.0.0.0", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule with private destination and source addresses",
			input: openstack.Compute{
				Metadata: types.NewTestMetadata(),
				Firewall: openstack.Firewall{
					Metadata: types.NewTestMetadata(),
					AllowRules: []openstack.Rule{
						{
							Metadata:    types.NewTestMetadata(),
							Enabled:     types.Bool(true, types.NewTestMetadata()),
							Destination: types.String("10.10.10.1", types.NewTestMetadata()),
							Source:      types.String("10.10.10.2", types.NewTestMetadata()),
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
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
