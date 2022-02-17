package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoSecretsInCustomData(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Secrets in custom data",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: types.NewTestMetadata(),
						VirtualMachine: compute.VirtualMachine{
							Metadata:   types.NewTestMetadata(),
							CustomData: types.String(`export DATABASE_PASSWORD=\"SomeSortOfPassword\"`, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "No secrets in custom data",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: types.NewTestMetadata(),
						VirtualMachine: compute.VirtualMachine{
							Metadata:   types.NewTestMetadata(),
							CustomData: types.String(`export GREETING="Hello there"`, types.NewTestMetadata()),
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
			results := CheckNoSecretsInCustomData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoSecretsInCustomData.Rule().LongID() {
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
