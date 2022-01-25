package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/openstack"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPlaintextPassword(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    openstack.Compute
		expected bool
	}{
		{
			name:     "positive result",
			input:    openstack.Compute{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    openstack.Compute{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.OpenStack.Compute = test.input
			results := CheckNoPlaintextPassword.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPlaintextPassword.Rule().LongID() {
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
