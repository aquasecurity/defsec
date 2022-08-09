package iam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

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
						Metadata: types2.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: types2.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata: types2.NewTestMetadata(),
										Member:   types2.String("user:test@example.com", types2.NewTestMetadata()),
										Role:     types2.String("some-role", types2.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata: types2.NewTestMetadata(),
										Members: []types2.StringValue{
											types2.String("user:test@example.com", types2.NewTestMetadata()),
										},
										Role: types2.String("some-role", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: types2.NewTestMetadata(),
								Member:   types2.String("user:test@example.com", types2.NewTestMetadata()),
								Role:     types2.String("some-role", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: types2.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata: types2.NewTestMetadata(),
										Member:   types2.String("user:test@example.com", types2.NewTestMetadata()),
										Role:     types2.String("some-role", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: types2.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata: types2.NewTestMetadata(),
										Members: []types2.StringValue{
											types2.String("user:test@example.com", types2.NewTestMetadata()),
										},
										Role: types2.String("some-role", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: types2.NewTestMetadata(),
								Member:   types2.String("group:test@example.com", types2.NewTestMetadata()),
								Role:     types2.String("some-role", types2.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: types2.NewTestMetadata(),
								Members: []types2.StringValue{
									types2.String("group:test@example.com", types2.NewTestMetadata()),
								},
								Role: types2.String("some-role", types2.NewTestMetadata()),
							},
						},
						Folders: []iam.Folder{
							{
								Metadata: types2.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata: types2.NewTestMetadata(),
										Members: []types2.StringValue{
											types2.String("group:test@example.com", types2.NewTestMetadata()),
										},
										Role: types2.String("some-role", types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoUserGrantedPermissions.Rule().LongID() {
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
