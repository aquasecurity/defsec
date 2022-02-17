package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoFolderLevelServiceAccountImpersonation(t *testing.T) {
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
						Metadata: types.NewTestMetadata(),
						Folders: []iam.Folder{
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
			name: "Member role set to service account token creator",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: types.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata:                      types.NewTestMetadata(),
										IncludesDefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
										Role:                          types.String("roles/iam.serviceAccountTokenCreator", types.NewTestMetadata()),
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
			name: "Member role set to something particular",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: types.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata: types.NewTestMetadata(),
										Role:     types.String("roles/nothingInParticular", types.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata:                      types.NewTestMetadata(),
										IncludesDefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
										Role:                          types.String("roles/nothingInParticular", types.NewTestMetadata()),
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
			results := CheckNoFolderLevelServiceAccountImpersonation.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoFolderLevelServiceAccountImpersonation.Rule().LongID() {
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
