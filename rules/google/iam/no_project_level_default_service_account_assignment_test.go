package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoProjectLevelDefaultServiceAccountAssignment(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Default service account disabled but default account used",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: types.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              types.NewTestMetadata(),
										DefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
										Member:                types.String("123-compute@developer.gserviceaccount.com", types.NewTestMetadata()),
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
			name: "Default account enabled",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: types.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata:                      types.NewTestMetadata(),
										IncludesDefaultServiceAccount: types.Bool(true, types.NewTestMetadata()),
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
			name: "Default accounts disabled and proper accounts provided",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: types.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              types.NewTestMetadata(),
										DefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
										Member:                types.String("proper@email.com", types.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata:                      types.NewTestMetadata(),
										IncludesDefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
										Members: []types.StringValue{
											types.String("proper@email.com", types.NewTestMetadata()),
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
			results := CheckNoProjectLevelDefaultServiceAccountAssignment.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckNoProjectLevelDefaultServiceAccountAssignment.Rule().LongID() {
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
