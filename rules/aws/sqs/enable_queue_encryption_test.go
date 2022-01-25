package sqs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/sqs"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableQueueEncryption(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    sqs.SQS
		expected bool
	}{
		{
			name:     "positive result",
			input:    sqs.SQS{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    sqs.SQS{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SQS = test.input
			results := CheckEnableQueueEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableQueueEncryption.Rule().LongID() {
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
