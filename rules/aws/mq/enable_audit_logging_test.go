package mq

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/mq"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAuditLogging(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    mq.MQ
		expected bool
	}{
		{
			name:     "positive result",
			input:    mq.MQ{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    mq.MQ{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.MQ = test.input
			results := CheckEnableAuditLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableAuditLogging.Rule().LongID() {
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
