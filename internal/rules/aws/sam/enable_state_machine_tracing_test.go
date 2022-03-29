package sam

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStateMachineTracing(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "State machine tracing disabled",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				StateMachines: []sam.StateMachine{
					{
						Metadata: types.NewTestMetadata(),
						Tracing: sam.TracingConfiguration{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "State machine tracing enabled",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				StateMachines: []sam.StateMachine{
					{
						Metadata: types.NewTestMetadata(),
						Tracing: sam.TracingConfiguration{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SAM = test.input
			results := CheckEnableStateMachineTracing.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStateMachineTracing.Rule().LongID() {
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
