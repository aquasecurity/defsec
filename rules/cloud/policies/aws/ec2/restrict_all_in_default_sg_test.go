package ec2

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRestrictAllInDefaultSG(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "default sg restricts all",
			input: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata: types.NewTestMetadata(),
						SecurityGroups: []ec2.SecurityGroup{
							{
								Metadata:     types.NewTestMetadata(),
								IsDefault:    types.Bool(true, types.NewTestMetadata()),
								IngressRules: nil,
								EgressRules:  nil,
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "default sg allows ingress",
			input: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata: types.NewTestMetadata(),
						SecurityGroups: []ec2.SecurityGroup{
							{
								Metadata:  types.NewTestMetadata(),
								IsDefault: types.Bool(true, types.NewTestMetadata()),
								IngressRules: []ec2.SecurityGroupRule{
									{},
								},
								EgressRules: nil,
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "default sg allows egress",
			input: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata: types.NewTestMetadata(),
						SecurityGroups: []ec2.SecurityGroup{
							{
								Metadata:     types.NewTestMetadata(),
								IsDefault:    types.Bool(true, types.NewTestMetadata()),
								IngressRules: nil,
								EgressRules: []ec2.SecurityGroupRule{
									{},
								},
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
			testState.AWS.EC2 = test.input
			results := CheckRestrictAllInDefaultSG.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRestrictAllInDefaultSG.Rule().LongID() {
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
