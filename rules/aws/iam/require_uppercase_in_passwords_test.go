package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckRequireUppercaseInPasswords(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "IAM password policy uppercase not required",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         types.NewTestMetadata(),
					RequireUppercase: types.Bool(false, types.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "IAM password policy uppercase required",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         types.NewTestMetadata(),
					RequireUppercase: types.Bool(true, types.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckRequireUppercaseInPasswords.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckRequireUppercaseInPasswords.Rule().LongID() {
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
