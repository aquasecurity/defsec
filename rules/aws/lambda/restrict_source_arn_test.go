package lambda

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/lambda"
	"github.com/aquasecurity/defsec/rules"
        "github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckRestrictSourceArn(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    lambda.Lambda
		expected bool
	}{
		{
			name:     "positive result",
			input:    lambda.Lambda{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    lambda.Lambda{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Lambda = test.input
			results := CheckRestrictSourceArn.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckRestrictSourceArn.Rule().LongID() {
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
