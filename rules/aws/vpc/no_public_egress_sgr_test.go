package vpc

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/vpc"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgressSgr(t *testing.T) {
	tests := []struct {
		name     string
		input    vpc.VPC
		expected bool
	}{
		{
			name: "AWS VPC security group rule with wildcard address",
			input: vpc.VPC{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []vpc.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						EgressRules: []vpc.SecurityGroupRule{
							{
								Metadata: types.NewTestMetadata(),
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
			name: "AWS VPC security group rule with private address",
			input: vpc.VPC{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []vpc.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						EgressRules: []vpc.SecurityGroupRule{
							{
								Metadata: types.NewTestMetadata(),
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
			testState.AWS.VPC = test.input
			results := CheckNoPublicEgressSgr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPublicEgressSgr.Rule().LongID() {
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
