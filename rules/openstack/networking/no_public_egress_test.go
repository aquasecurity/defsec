package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/openstack"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    openstack.Networking
		expected bool
	}{
		{
			name: "Security group rule missing address",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  types.NewTestMetadata(),
								IsIngress: types.Bool(false, types.NewTestMetadata()),
								CIDR:      types.String("", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule with private address",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  types.NewTestMetadata(),
								IsIngress: types.Bool(false, types.NewTestMetadata()),
								CIDR:      types.String("10.10.0.1", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule with single public address",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  types.NewTestMetadata(),
								IsIngress: types.Bool(false, types.NewTestMetadata()),
								CIDR:      types.String("8.8.8.8", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule with large public cidr",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  types.NewTestMetadata(),
								IsIngress: types.Bool(false, types.NewTestMetadata()),
								CIDR:      types.String("80.0.0.0/8", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.OpenStack.Networking = test.input
			results := CheckNoPublicEgress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckNoPublicEgress.Rule().LongID() {
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
