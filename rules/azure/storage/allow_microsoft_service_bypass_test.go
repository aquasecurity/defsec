package storage

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/storage"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckAllowMicrosoftServiceBypass(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name:     "positive result",
			input:    storage.Storage{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    storage.Storage{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.Storage = test.input
			results := CheckAllowMicrosoftServiceBypass.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckAllowMicrosoftServiceBypass.Rule().LongID() {
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
