package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/digitalocean/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckAutoUpgrade(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name:     "positive result",
			input:    compute.Compute{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    compute.Compute{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.DigitalOcean.Compute = test.input
			results := CheckAutoUpgrade.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckAutoUpgrade.Rule().LongID() {
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
