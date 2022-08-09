package compute

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableShieldedVMVTPM(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Instance shielded VM VTPM disabled",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: types2.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:    types2.NewTestMetadata(),
							VTPMEnabled: types2.Bool(false, types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance shielded VM VTPM enabled",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: types2.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:    types2.NewTestMetadata(),
							VTPMEnabled: types2.Bool(true, types2.NewTestMetadata()),
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
			testState.Google.Compute = test.input
			results := CheckEnableShieldedVMVTPM.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableShieldedVMVTPM.Rule().LongID() {
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
