package dns

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/dns"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoRsaSha1(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    dns.DNS
		expected bool
	}{
		{
			name:     "positive result",
			input:    dns.DNS{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    dns.DNS{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.DNS = test.input
			results := CheckNoRsaSha1.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoRsaSha1.Rule().LongID() {
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
