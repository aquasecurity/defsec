package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckProjectLevelOslogin(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Compute OS login disabled",
			input: compute.Compute{
				ProjectMetadata: compute.ProjectMetadata{
					Metadata:      defsecTypes.NewTestMetadata(),
					EnableOSLogin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Compute OS login enabled",
			input: compute.Compute{
				ProjectMetadata: compute.ProjectMetadata{
					Metadata:      defsecTypes.NewTestMetadata(),
					EnableOSLogin: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.Compute = test.input
			results := CheckProjectLevelOslogin.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckProjectLevelOslogin.Rule().LongID() {
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
