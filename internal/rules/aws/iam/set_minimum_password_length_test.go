package iam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSetMinimumPasswordLength(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Minimum password length set to 8",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:      types2.NewTestMetadata(),
					MinimumLength: types2.Int(8, types2.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Minimum password length set to 15",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:      types2.NewTestMetadata(),
					MinimumLength: types2.Int(15, types2.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckSetMinimumPasswordLength.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSetMinimumPasswordLength.Rule().LongID() {
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
