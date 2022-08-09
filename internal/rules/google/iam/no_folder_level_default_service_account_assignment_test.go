package iam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoFolderLevelDefaultServiceAccountAssignment(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Default service account enabled",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types2.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: types2.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              types2.NewTestMetadata(),
										DefaultServiceAccount: types2.Bool(true, types2.NewTestMetadata()),
										Member:                types2.String("proper@email.com", types2.NewTestMetadata()),
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
			name: "Default service account disabled but default account data provided",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types2.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: types2.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              types2.NewTestMetadata(),
										DefaultServiceAccount: types2.Bool(false, types2.NewTestMetadata()),
										Member:                types2.String("123-compute@developer.gserviceaccount.com", types2.NewTestMetadata()),
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
			name: "Default service account disabled but default account data provided #2",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types2.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: types2.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata:                      types2.NewTestMetadata(),
										IncludesDefaultServiceAccount: types2.Bool(false, types2.NewTestMetadata()),
										Members: []types2.StringValue{
											types2.String("123-compute@developer.gserviceaccount.com", types2.NewTestMetadata())},
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
			name: "Default service account disabled and proper account data provided",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types2.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: types2.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              types2.NewTestMetadata(),
										DefaultServiceAccount: types2.Bool(false, types2.NewTestMetadata()),
										Member:                types2.String("proper@email.com", types2.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata:                      types2.NewTestMetadata(),
										IncludesDefaultServiceAccount: types2.Bool(false, types2.NewTestMetadata()),
										Members: []types2.StringValue{
											types2.String("proper@account.com", types2.NewTestMetadata()),
										},
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
			results := CheckNoFolderLevelDefaultServiceAccountAssignment.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoFolderLevelDefaultServiceAccountAssignment.Rule().LongID() {
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
