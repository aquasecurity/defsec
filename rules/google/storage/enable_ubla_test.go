package storage

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/storage"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableUbla(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Uniform bucket level access disabled",
			input: storage.Storage{
				Metadata: types.NewTestMetadata(),
				Buckets: []storage.Bucket{
					{
						Metadata:                       types.NewTestMetadata(),
						EnableUniformBucketLevelAccess: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Uniform bucket level access enabled",
			input: storage.Storage{
				Metadata: types.NewTestMetadata(),
				Buckets: []storage.Bucket{
					{
						Metadata:                       types.NewTestMetadata(),
						EnableUniformBucketLevelAccess: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckEnableUbla.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableUbla.Rule().LongID() {
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
