package compute

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/openstack"
	"github.com/aquasecurity/defsec/pkg/scan"

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
						Metadata: types2.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  types2.NewTestMetadata(),
								IsIngress: types2.Bool(false, types2.NewTestMetadata()),
								CIDR:      types2.String("", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  types2.NewTestMetadata(),
								IsIngress: types2.Bool(false, types2.NewTestMetadata()),
								CIDR:      types2.String("10.10.0.1", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  types2.NewTestMetadata(),
								IsIngress: types2.Bool(false, types2.NewTestMetadata()),
								CIDR:      types2.String("8.8.8.8", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  types2.NewTestMetadata(),
								IsIngress: types2.Bool(false, types2.NewTestMetadata()),
								CIDR:      types2.String("80.0.0.0/8", types2.NewTestMetadata()),
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
