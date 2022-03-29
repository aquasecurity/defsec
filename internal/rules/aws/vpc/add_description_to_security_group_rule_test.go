package vpc

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/vpc"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAddDescriptionToSecurityGroupRule(t *testing.T) {
	tests := []struct {
		name     string
		input    vpc.VPC
		expected bool
	}{
		{
			name: "AWS VPC security group rule has no description",
			input: vpc.VPC{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []vpc.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						IngressRules: []vpc.SecurityGroupRule{
							{
								Metadata:    types.NewTestMetadata(),
								Description: types.String("", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC security group rule has description",
			input: vpc.VPC{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []vpc.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						IngressRules: []vpc.SecurityGroupRule{
							{
								Metadata:    types.NewTestMetadata(),
								Description: types.String("some description", types.NewTestMetadata()),
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
