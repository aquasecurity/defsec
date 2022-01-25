package elb

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckDropInvalidHeaders(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    elb.ELB
		expected bool
	}{
		{
			name:     "positive result",
			input:    elb.ELB{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    elb.ELB{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.ELB = test.input
			results := CheckDropInvalidHeaders.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Rule().LongID() == CheckDropInvalidHeaders.Rule().LongID() {
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
