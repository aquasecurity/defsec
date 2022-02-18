package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoUserGrantedPermissions(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Permissions granted to users",
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
										Member:   types.String("user:test@example.com", types.NewTestMetadata()),
										Role:     types.String("some-role", types.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata: types.NewTestMetadata(),
										Members: []types.StringValue{
											types.String("user:test@example.com", types.NewTestMetadata()),
										},
										Role: types.String("some-role", types.NewTestMetadata()),
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
			name: "Permissions granted to users #2",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: types.NewTestMetadata(),
								Member:   types.String("user:test@example.com", types.NewTestMetadata()),
								Role:     types.String("some-role", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Permissions granted to users #3",
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
										Member:   types.String("user:test@example.com", types.NewTestMetadata()),
										Role:     types.String("some-role", types.NewTestMetadata()),
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
			name: "Permissions granted to users #4",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: types.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata: types.NewTestMetadata(),
										Members: []types.StringValue{
											types.String("user:test@example.com", types.NewTestMetadata()),
										},
										Role: types.String("some-role", types.NewTestMetadata()),
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
			name: "Permissions granted on groups",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: types.NewTestMetadata(),
								Member:   types.String("group:test@example.com", types.NewTestMetadata()),
								Role:     types.String("some-role", types.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: types.NewTestMetadata(),
								Members: []types.StringValue{
									types.String("group:test@example.com", types.NewTestMetadata()),
								},
								Role: types.String("some-role", types.NewTestMetadata()),
							},
						},
						Folders: []iam.Folder{
							{
								Metadata: types.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata: types.NewTestMetadata(),
										Members: []types.StringValue{
											types.String("group:test@example.com", types.NewTestMetadata()),
										},
										Role: types.String("some-role", types.NewTestMetadata()),
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
			results := CheckNoUserGrantedPermissions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoUserGrantedPermissions.Rule().LongID() {
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
