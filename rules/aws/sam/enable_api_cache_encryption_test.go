package sam

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/sam"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableApiCacheEncryption(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name:     "positive result",
			input:    sam.SAM{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    sam.SAM{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SAM = test.input
			results := CheckEnableApiCacheEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Rule().LongID() == CheckEnableApiCacheEncryption.Rule().LongID() {
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
