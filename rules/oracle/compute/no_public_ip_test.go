package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/oracle"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
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
				Metadata: types.NewTestMetadata(),
				AddressReservations: []oracle.AddressReservation{
					{
						Metadata: types.NewTestMetadata(),
						Pool:     types.String("public-ippool", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Compute instance cloud reservation pool",
			input: oracle.Compute{
				Metadata: types.NewTestMetadata(),
				AddressReservations: []oracle.AddressReservation{
					{
						Metadata: types.NewTestMetadata(),
						Pool:     types.String("cloud-ippool", types.NewTestMetadata()),
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
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPublicIp.Rule().LongID() {
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
