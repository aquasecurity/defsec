package sam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				StateMachines: []sam.StateMachine{
					{
						Metadata: types2.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       types2.NewTestMetadata(),
							LoggingEnabled: types2.Bool(false, types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "State machine logging enabled",
			input: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: types2.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       types2.NewTestMetadata(),
							LoggingEnabled: types2.Bool(true, types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStateMachineLogging.Rule().LongID() {
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
