package msk

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/msk"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableLogging(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    msk.MSK
		expected bool
	}{
		{
			name:     "positive result",
			input:    msk.MSK{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    msk.MSK{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.MSK = test.input
			results := CheckEnableLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Rule().LongID() == CheckEnableLogging.Rule().LongID() {
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
