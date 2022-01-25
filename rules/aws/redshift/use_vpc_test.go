package redshift

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/redshift"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckUsesVPC(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    redshift.Redshift
		expected bool
	}{
		{
			name:     "positive result",
			input:    redshift.Redshift{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    redshift.Redshift{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Redshift = test.input
			results := CheckUsesVPC.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Rule().LongID() == CheckUsesVPC.Rule().LongID() {
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
