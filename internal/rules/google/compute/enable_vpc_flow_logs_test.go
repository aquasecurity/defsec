package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableVPCFlowLogs(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Subnetwork VPC flow logs disabled",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: types.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       types.NewTestMetadata(),
								EnableFlowLogs: types.Bool(false, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Subnetwork VPC flow logs enabled",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: types.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       types.NewTestMetadata(),
								EnableFlowLogs: types.Bool(true, types.NewTestMetadata()),
							},
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
			results := CheckEnableVPCFlowLogs.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableVPCFlowLogs.Rule().LongID() {
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
