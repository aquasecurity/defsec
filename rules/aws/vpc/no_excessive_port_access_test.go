package vpc

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/vpc"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoExcessivePortAccess(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    vpc.VPC
		expected bool
	}{
		{
			name:     "positive result",
			input:    vpc.VPC{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    vpc.VPC{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.VPC = test.input
			results := CheckNoExcessivePortAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoExcessivePortAccess.Rule().LongID() {
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
