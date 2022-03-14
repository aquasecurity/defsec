package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoSerialPort(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Instance serial port enabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Instances: []compute.Instance{
					{
						Metadata:         types.NewTestMetadata(),
						EnableSerialPort: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance serial port disabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Instances: []compute.Instance{
					{
						Metadata:         types.NewTestMetadata(),
						EnableSerialPort: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.Compute = test.input
			results := CheckNoSerialPort.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckNoSerialPort.Rule().LongID() {
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
