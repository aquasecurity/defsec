package compute

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/oracle"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIp(t *testing.T) {
	tests := []struct {
		name     string
		input    oracle.Compute
		expected bool
	}{
		{
			name: "Compute instance public reservation pool",
			input: oracle.Compute{
				AddressReservations: []oracle.AddressReservation{
					{
						Metadata: types2.NewTestMetadata(),
						Pool:     types2.String("public-ippool", types2.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Compute instance cloud reservation pool",
			input: oracle.Compute{
				AddressReservations: []oracle.AddressReservation{
					{
						Metadata: types2.NewTestMetadata(),
						Pool:     types2.String("cloud-ippool", types2.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Oracle.Compute = test.input
			results := CheckNoPublicIp.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIp.Rule().LongID() {
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
