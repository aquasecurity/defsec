package repositories

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/github"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckPrivate(t *testing.T) {
	tests := []struct {
		name     string
		input    []github.Repository
		expected bool
	}{
		{
			name: "Public repository",
			input: []github.Repository{
				{
					Metadata: types.NewTestMetadata(),
					Public:   types.Bool(true, types.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Private repository",
			input: []github.Repository{
				{
					Metadata: types.NewTestMetadata(),
					Public:   types.Bool(false, types.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.GitHub.Repositories = test.input
			results := CheckPrivate.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckPrivate.Rule().LongID() {
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
