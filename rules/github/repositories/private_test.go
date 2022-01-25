package repositories

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckPrivate(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    []github.Repository
		expected bool
	}{
		{
			name:     "positive result",
			input:    []github.Repository{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    []github.Repository{},
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
				if result.Rule().LongID() == CheckPrivate.Rule().LongID() {
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
