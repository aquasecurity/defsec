package iam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

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
						Metadata: types2.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: types2.NewTestMetadata(),
								Role:     types2.String("roles/owner", types2.NewTestMetadata()),
								Member:   types2.String("serviceAccount:${google_service_account.test.email}", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: types2.NewTestMetadata(),
								Projects: []iam.Project{
									{
										Metadata: types2.NewTestMetadata(),
										Bindings: []iam.Binding{
											{
												Metadata: types2.NewTestMetadata(),
												Role:     types2.String("roles/editor", types2.NewTestMetadata()),
												Members: []types2.StringValue{
													types2.String("serviceAccount:${google_service_account.test.email}", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: types2.NewTestMetadata(),
								Projects: []iam.Project{
									{
										Metadata: types2.NewTestMetadata(),
										Members: []iam.Member{
											{
												Metadata: types2.NewTestMetadata(),
												Role:     types2.String("roles/owner", types2.NewTestMetadata()),
												Member:   types2.String("proper@email.com", types2.NewTestMetadata()),
											},
										},
										Bindings: []iam.Binding{
											{
												Metadata: types2.NewTestMetadata(),
												Role:     types2.String("roles/logging.logWriter", types2.NewTestMetadata()),
												Members: []types2.StringValue{
													types2.String("serviceAccount:${google_service_account.test.email}", types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPrivilegedServiceAccounts.Rule().LongID() {
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
