package ssm

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/ssm"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckSecretUseCustomerKey(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    ssm.SSM
		expected bool
	}{
		{
			name:     "positive result",
			input:    ssm.SSM{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    ssm.SSM{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SSM = test.input
			results := CheckSecretUseCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Rule().LongID() == CheckSecretUseCustomerKey.Rule().LongID() {
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
