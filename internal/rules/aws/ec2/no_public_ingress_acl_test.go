package ec2

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "AWS VPC network ACL rule with wildcard address",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: types.NewTestMetadata(),
								Type:     types.String(ec2.TypeIngress, types.NewTestMetadata()),
								Action:   types.String(ec2.ActionAllow, types.NewTestMetadata()),
								CIDRs: []types.StringValue{
									types.String("0.0.0.0/0", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with private address",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: types.NewTestMetadata(),
								Type:     types.String(ec2.TypeIngress, types.NewTestMetadata()),
								Action:   types.String(ec2.ActionAllow, types.NewTestMetadata()),
								CIDRs: []types.StringValue{
									types.String("10.0.0.0/16", types.NewTestMetadata()),
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
			testState.AWS.EC2 = test.input
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
