package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoUserAttachedPolicies(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "user without policies attached",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: types.NewTestMetadata(),
						Name:     types.String("example", types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "user with a policy attached",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: types.NewTestMetadata(),
						Name:     types.String("example", types.NewTestMetadata()),
						Policies: []iam.Policy{
							{
								Metadata: types.NewTestMetadata(),
								Name:     types.String("another.policy", types.NewTestMetadata()),
								Document: iam.Document{
									Metadata: types.NewTestMetadata(),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := checkNoUserAttachedPolicies.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkNoUserAttachedPolicies.Rule().LongID() {
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
