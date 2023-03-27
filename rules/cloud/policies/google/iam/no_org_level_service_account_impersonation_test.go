package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoOrgLevelServiceAccountImpersonation(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Member role set to service account user",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Role:     defsecTypes.String("roles/iam.serviceAccountUser", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Member role set to service account token creator",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Role:     defsecTypes.String("roles/iam.serviceAccountTokenCreator", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},

		{
			name: "Member roles custom set",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Role:     defsecTypes.String("roles/some-custom-role", defsecTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Role:     defsecTypes.String("roles/some-custom-role", defsecTypes.NewTestMetadata()),
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
			testState.Google.IAM = test.input
			results := CheckNoOrgLevelServiceAccountImpersonation.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoOrgLevelServiceAccountImpersonation.Rule().LongID() {
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
