package computing

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/computing"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAddDescriptionToSecurityGroupRule(t *testing.T) {
	tests := []struct {
		name     string
		input    computing.Computing
		expected bool
	}{
		{
			name: "NIFCLOUD security group rule has no description",
			input: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
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
			name: "NIFCLOUD security group rule has description",
			input: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
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
			testState.Nifcloud.Computing = test.input
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
