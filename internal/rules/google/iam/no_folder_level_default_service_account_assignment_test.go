package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

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
						Metadata: defsecTypes.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              defsecTypes.NewTestMetadata(),
										DefaultServiceAccount: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
										Member:                defsecTypes.String("proper@email.com", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              defsecTypes.NewTestMetadata(),
										DefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
										Member:                defsecTypes.String("123-compute@developer.gserviceaccount.com", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata:                      defsecTypes.NewTestMetadata(),
										IncludesDefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
										Members: []defsecTypes.StringValue{
											defsecTypes.String("123-compute@developer.gserviceaccount.com", defsecTypes.NewTestMetadata())},
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
						Metadata: defsecTypes.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              defsecTypes.NewTestMetadata(),
										DefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
										Member:                defsecTypes.String("proper@email.com", defsecTypes.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata:                      defsecTypes.NewTestMetadata(),
										IncludesDefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
										Members: []defsecTypes.StringValue{
											defsecTypes.String("proper@account.com", defsecTypes.NewTestMetadata()),
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
