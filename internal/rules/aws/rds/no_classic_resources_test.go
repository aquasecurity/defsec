package rds

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoClassicResources(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "Classic resources present",
			input: rds.RDS{
				Metadata: types.NewTestMetadata(),
				Classic: rds.Classic{
					Metadata: types.NewTestMetadata(),
					DBSecurityGroups: []rds.DBSecurityGroup{
						{
							Metadata: types.NewTestMetadata(),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "no Classic resources present",
			input: rds.RDS{
				Metadata: types.NewTestMetadata(),
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.RDS = test.input
			results := CheckNoClassicResources.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoClassicResources.Rule().LongID() {
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
