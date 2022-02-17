package sam

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/aws/sam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStateMachineLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "State machine logging disabled",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				StateMachines: []sam.StateMachine{
					{
						Metadata: types.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       types.NewTestMetadata(),
							LoggingEnabled: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "State machine logging enabled",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				StateMachines: []sam.StateMachine{
					{
						Metadata: types.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       types.NewTestMetadata(),
							LoggingEnabled: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckEnableStateMachineLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableStateMachineLogging.Rule().LongID() {
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
