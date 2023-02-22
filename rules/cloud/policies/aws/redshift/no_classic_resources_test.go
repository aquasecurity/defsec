package redshift

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoClassicResources(t *testing.T) {
	tests := []struct {
		name     string
		input    redshift.Redshift
		expected bool
	}{
		{
			name: "security groups present",
			input: redshift.Redshift{
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
					},
				},
			},
			expected: true,
		},
		{
			name:     "no security groups",
			input:    redshift.Redshift{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Redshift = test.input
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
