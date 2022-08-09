package dns

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/dns"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableDnssec(t *testing.T) {
	tests := []struct {
		name     string
		input    dns.DNS
		expected bool
	}{
		{
			name: "DNSSec disabled and required when visibility explicitly public",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   types2.NewTestMetadata(),
						Visibility: types2.String("public", types2.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(false, types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "DNSSec enabled",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   types2.NewTestMetadata(),
						Visibility: types2.String("public", types2.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(true, types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "DNSSec not required when private",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   types2.NewTestMetadata(),
						Visibility: types2.String("private", types2.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(true, types2.NewTestMetadata()),
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
			testState.Google.DNS = test.input
			results := CheckEnableDnssec.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableDnssec.Rule().LongID() {
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
