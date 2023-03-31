package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

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
						Metadata: defsecTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Role:     defsecTypes.String("roles/owner", defsecTypes.NewTestMetadata()),
								Member:   defsecTypes.String("serviceAccount:${google_service_account.test.email}", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Projects: []iam.Project{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Bindings: []iam.Binding{
											{
												Metadata: defsecTypes.NewTestMetadata(),
												Role:     defsecTypes.String("roles/editor", defsecTypes.NewTestMetadata()),
												Members: []defsecTypes.StringValue{
													defsecTypes.String("serviceAccount:${google_service_account.test.email}", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Projects: []iam.Project{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Members: []iam.Member{
											{
												Metadata: defsecTypes.NewTestMetadata(),
												Role:     defsecTypes.String("roles/owner", defsecTypes.NewTestMetadata()),
												Member:   defsecTypes.String("proper@email.com", defsecTypes.NewTestMetadata()),
											},
										},
										Bindings: []iam.Binding{
											{
												Metadata: defsecTypes.NewTestMetadata(),
												Role:     defsecTypes.String("roles/logging.logWriter", defsecTypes.NewTestMetadata()),
												Members: []defsecTypes.StringValue{
													defsecTypes.String("serviceAccount:${google_service_account.test.email}", defsecTypes.NewTestMetadata()),
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
