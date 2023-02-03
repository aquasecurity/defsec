package ec2

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAddDescriptionToSecurityGroupRule(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "AWS VPC security group rule has no description",
			input: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    defsecTypes.NewTestMetadata(),
								Description: defsecTypes.String("", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC security group rule has description",
			input: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    defsecTypes.NewTestMetadata(),
								Description: defsecTypes.String("some description", defsecTypes.NewTestMetadata()),
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
			results := CheckAddDescriptionToSecurityGroupRule.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAddDescriptionToSecurityGroupRule.Rule().LongID() {
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
