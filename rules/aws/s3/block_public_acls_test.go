package s3

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckPublicACLsAreBlocked(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    s3.S3
		expected bool
	}{
		{
			name:     "positive result",
			input:    s3.S3{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    s3.S3{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.S3 = test.input
			results := CheckPublicACLsAreBlocked.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckPublicACLsAreBlocked.Rule().LongID() {
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
