package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
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
				Metadata: types.NewTestMetadata(),
				ProjectMetadata: compute.ProjectMetadata{
					Metadata:      types.NewTestMetadata(),
					EnableOSLogin: types.Bool(false, types.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Compute OS login enabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				ProjectMetadata: compute.ProjectMetadata{
					Metadata:      types.NewTestMetadata(),
					EnableOSLogin: types.Bool(true, types.NewTestMetadata()),
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
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckProjectLevelOslogin.Rule().LongID() {
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
