package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireNumbersInPasswords(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "IAM password policy numbers not required",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:       types.NewTestMetadata(),
					RequireNumbers: types.Bool(false, types.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "IAM password policy numbers required",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:       types.NewTestMetadata(),
					RequireNumbers: types.Bool(true, types.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckRequireNumbersInPasswords.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireNumbersInPasswords.Rule().LongID() {
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
