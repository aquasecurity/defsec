package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckSetMaxPasswordAge(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Password expires in 99 days",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:   types.NewTestMetadata(),
					MaxAgeDays: types.Int(99, types.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Password expires in 60 days",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:   types.NewTestMetadata(),
					MaxAgeDays: types.Int(60, types.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckSetMaxPasswordAge.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckSetMaxPasswordAge.Rule().LongID() {
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
