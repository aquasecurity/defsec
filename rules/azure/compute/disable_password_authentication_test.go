package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckDisablePasswordAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Linux VM password authentication enabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: types.NewTestMetadata(),
						OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
							Metadata:                      types.NewTestMetadata(),
							DisablePasswordAuthentication: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Linux VM password authentication disabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: types.NewTestMetadata(),
						OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
							Metadata:                      types.NewTestMetadata(),
							DisablePasswordAuthentication: types.Bool(true, types.NewTestMetadata()),
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
			testState.Azure.Compute = test.input
			results := CheckDisablePasswordAuthentication.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckDisablePasswordAuthentication.Rule().LongID() {
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
