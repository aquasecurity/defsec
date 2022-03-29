package ec2

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoSecretsInUserData(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "positive result",
			input: ec2.EC2{
				Metadata: types.NewTestMetadata(),
				Instances: []ec2.Instance{
					{
						Metadata: types.NewTestMetadata(),
						UserData: types.String(`<<EOF
						export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
						export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
						export AWS_DEFAULT_REGION=us-west-2
						EOF`, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "negative result",
			input: ec2.EC2{
				Metadata: types.NewTestMetadata(),
				Instances: []ec2.Instance{
					{
						Metadata: types.NewTestMetadata(),
						UserData: types.String(`<<EOF
						export GREETING=hello
						EOF`, types.NewTestMetadata()),
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
			results := CheckNoSecretsInUserData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoSecretsInUserData.Rule().LongID() {
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
