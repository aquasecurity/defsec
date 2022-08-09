package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPasswordReuse(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "IAM with 1 password that can't be reused (min)",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:             defsecTypes.NewTestMetadata(),
					ReusePreventionCount: defsecTypes.Int(1, defsecTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "IAM with 5 passwords that can't be reused",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:             defsecTypes.NewTestMetadata(),
					ReusePreventionCount: defsecTypes.Int(5, defsecTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckNoPasswordReuse.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPasswordReuse.Rule().LongID() {
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
