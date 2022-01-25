package cloudfront

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableLogging(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    cloudfront.Cloudfront
		expected bool
	}{
		{
			name:     "positive result",
			input:    cloudfront.Cloudfront{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    cloudfront.Cloudfront{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Cloudfront = test.input
			results := CheckEnableLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableLogging.Rule().LongID() {
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
