package storage

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/providers/google/storage"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Members set to all authenticated users",
			input: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: types.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: types.NewTestMetadata(),
								Members: []types.StringValue{
									types.String("allAuthenticatedUsers", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Members set to all users",
			input: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: types.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: types.NewTestMetadata(),
								Member:   types.String("allUsers", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Members set to specific users",
			input: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: types.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: types.NewTestMetadata(),
								Members: []types.StringValue{
									types.String("user:jane@example.com", types.NewTestMetadata()),
								},
							},
						},
						Members: []iam.Member{
							{
								Metadata: types.NewTestMetadata(),
								Member:   types.String("user:john@example.com", types.NewTestMetadata()),
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
			testState.Google.Storage = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
