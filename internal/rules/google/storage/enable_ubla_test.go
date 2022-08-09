package storage

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/storage"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				Buckets: []storage.Bucket{
					{
						Metadata:                       types2.NewTestMetadata(),
						EnableUniformBucketLevelAccess: types2.Bool(false, types2.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Uniform bucket level access enabled",
			input: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata:                       types2.NewTestMetadata(),
						EnableUniformBucketLevelAccess: types2.Bool(true, types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableUbla.Rule().LongID() {
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
