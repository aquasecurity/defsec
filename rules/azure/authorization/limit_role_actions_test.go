package authorization

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/authorization"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckLimitRoleActions(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    authorization.Authorization
		expected bool
	}{
		{
			name:     "positive result",
			input:    authorization.Authorization{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    authorization.Authorization{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.Authorization = test.input
			results := CheckLimitRoleActions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Rule().LongID() == CheckLimitRoleActions.Rule().LongID() {
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
