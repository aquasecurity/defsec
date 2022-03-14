package vpc

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/vpc"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckAddDescriptionToSecurityGroup(t *testing.T) {
	tests := []struct {
		name     string
		input    vpc.VPC
		expected bool
	}{
		{
			name: "AWS VPC security group with no description provided",
			input: vpc.VPC{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []vpc.SecurityGroup{
					{
						Metadata:    types.NewTestMetadata(),
						Description: types.String("", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC security group with default description",
			input: vpc.VPC{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []vpc.SecurityGroup{
					{
						Metadata:    types.NewTestMetadata(),
						Description: types.String("Managed by Terraform", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC security group with proper description",
			input: vpc.VPC{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []vpc.SecurityGroup{
					{
						Metadata:    types.NewTestMetadata(),
						Description: types.String("some proper description", types.NewTestMetadata()),
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
			results := CheckAddDescriptionToSecurityGroup.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckAddDescriptionToSecurityGroup.Rule().LongID() {
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
