package container

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/container"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckConfiguredNetworkPolicy(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name:     "positive result",
			input:    container.Container{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    container.Container{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.Container = test.input
			results := CheckConfiguredNetworkPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckConfiguredNetworkPolicy.Rule().LongID() {
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
