package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/azure/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableDiskEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Managed disk encryption disabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				ManagedDisks: []compute.ManagedDisk{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: compute.Encryption{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Managed disk encryption enabled",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				ManagedDisks: []compute.ManagedDisk{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: compute.Encryption{
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
			testState.Azure.Compute = test.input
			results := CheckEnableDiskEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableDiskEncryption.Rule().LongID() {
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
