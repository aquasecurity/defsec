package rds

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/rds"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckBackupRetentionSpecified(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name:     "positive result",
			input:    rds.RDS{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    rds.RDS{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.RDS = test.input
			results := CheckBackupRetentionSpecified.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Rule().LongID() == CheckBackupRetentionSpecified.Rule().LongID() {
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
