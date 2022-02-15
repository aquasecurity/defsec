package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoProjectLevelServiceAccountImpersonation(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Project member role set to service account user",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: types.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata: types.NewTestMetadata(),
										Role:     types.String("roles/iam.serviceAccountUser", types.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Project member role set to service account token creator",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: types.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata: types.NewTestMetadata(),
										Role:     types.String("roles/iam.serviceAccountTokenCreator", types.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Project members set to custom roles",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: types.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata: types.NewTestMetadata(),
										Role:     types.String("roles/specific-role", types.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata: types.NewTestMetadata(),
										Role:     types.String("roles/specific-role", types.NewTestMetadata()),
									},
								},
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
			results := CheckNoProjectLevelServiceAccountImpersonation.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoProjectLevelServiceAccountImpersonation.Rule().LongID() {
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
