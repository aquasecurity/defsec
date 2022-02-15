package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoDefaultNetwork(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Project automatic network creation enabled",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata:          types.NewTestMetadata(),
								AutoCreateNetwork: types.Bool(true, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Project automatic network creation enabled #2",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: types.NewTestMetadata(),
								Projects: []iam.Project{
									{
										Metadata:          types.NewTestMetadata(),
										AutoCreateNetwork: types.Bool(false, types.NewTestMetadata()),
									},
								},
								Folders: []iam.Folder{
									{
										Metadata: types.NewTestMetadata(),
										Projects: []iam.Project{
											{
												Metadata:          types.NewTestMetadata(),
												AutoCreateNetwork: types.Bool(true, types.NewTestMetadata()),
											},
										},
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
			name: "Project automatic network creation disabled",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata:          types.NewTestMetadata(),
								AutoCreateNetwork: types.Bool(false, types.NewTestMetadata()),
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
			results := CheckNoDefaultNetwork.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoDefaultNetwork.Rule().LongID() {
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
