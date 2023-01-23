package ec2

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoExcessivePortAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("-1", defsecTypes.NewTestMetadata()),
								Type:     defsecTypes.String("egress", defsecTypes.NewTestMetadata()),
								Action:   defsecTypes.String("allow", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("all", defsecTypes.NewTestMetadata()),
								Type:     defsecTypes.String("egress", defsecTypes.NewTestMetadata()),
								Action:   defsecTypes.String("allow", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with tcp protocol",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("tcp", defsecTypes.NewTestMetadata()),
								Type:     defsecTypes.String("egress", defsecTypes.NewTestMetadata()),
								Action:   defsecTypes.String("allow", defsecTypes.NewTestMetadata()),
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
			results := CheckNoExcessivePortAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoExcessivePortAccess.Rule().LongID() {
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
