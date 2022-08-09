package iam

import (
	"testing"
	"time"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceUserMFA(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "user logged in without mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("other", types2.NewTestMetadata()),
						LastAccess: types2.Time(time.Now(), types2.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "user without mfa never logged in",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("other", types2.NewTestMetadata()),
						LastAccess: types2.TimeUnresolvable(types2.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "user with mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: types2.NewTestMetadata(),
						Name:     types2.String("root", types2.NewTestMetadata()),
						MFADevices: []iam.MFADevice{
							{
								Metadata: types2.NewTestMetadata(),
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
			testState.AWS.IAM = test.input
			results := CheckEnforceUserMFA.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforceUserMFA.Rule().LongID() {
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
