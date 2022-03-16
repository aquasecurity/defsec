package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPrivilegedServiceAccounts(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Service account granted owner role",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: types.NewTestMetadata(),
								Role:     types.String("roles/owner", types.NewTestMetadata()),
								Member:   types.String("serviceAccount:${google_service_account.test.email}", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Service account granted editor role",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: types.NewTestMetadata(),
								Projects: []iam.Project{
									{
										Metadata: types.NewTestMetadata(),
										Bindings: []iam.Binding{
											{
												Metadata: types.NewTestMetadata(),
												Role:     types.String("roles/editor", types.NewTestMetadata()),
												Members: []types.StringValue{
													types.String("serviceAccount:${google_service_account.test.email}", types.NewTestMetadata()),
												},
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
			name: "No service account with excessive privileges",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: types.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: types.NewTestMetadata(),
								Projects: []iam.Project{
									{
										Metadata: types.NewTestMetadata(),
										Members: []iam.Member{
											{
												Metadata: types.NewTestMetadata(),
												Role:     types.String("roles/owner", types.NewTestMetadata()),
												Member:   types.String("proper@email.com", types.NewTestMetadata()),
											},
										},
										Bindings: []iam.Binding{
											{
												Metadata: types.NewTestMetadata(),
												Role:     types.String("roles/logging.logWriter", types.NewTestMetadata()),
												Members: []types.StringValue{
													types.String("serviceAccount:${google_service_account.test.email}", types.NewTestMetadata()),
												},
											},
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
			results := CheckNoPrivilegedServiceAccounts.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckNoPrivilegedServiceAccounts.Rule().LongID() {
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
