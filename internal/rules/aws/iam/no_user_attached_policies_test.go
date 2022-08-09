package iam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

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
						Metadata: types2.NewTestMetadata(),
						Name:     types2.String("example", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Name:     types2.String("example", types2.NewTestMetadata()),
						Policies: []iam.Policy{
							{
								Metadata: types2.NewTestMetadata(),
								Name:     types2.String("another.policy", types2.NewTestMetadata()),
								Document: iam.Document{
									Metadata: types2.NewTestMetadata(),
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
