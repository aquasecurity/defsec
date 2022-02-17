package dns

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/google/dns"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoRsaSha1(t *testing.T) {
	tests := []struct {
		name     string
		input    dns.DNS
		expected bool
	}{
		{
			name: "Zone signing using RSA SHA1 key",
			input: dns.DNS{
				Metadata: types.NewTestMetadata(),
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: types.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: types.NewTestMetadata(),
							DefaultKeySpecs: dns.KeySpecs{
								Metadata: types.NewTestMetadata(),
								KeySigningKey: dns.Key{
									Metadata:  types.NewTestMetadata(),
									Algorithm: types.String("rsasha1", types.NewTestMetadata()),
								},
								ZoneSigningKey: dns.Key{
									Metadata:  types.NewTestMetadata(),
									Algorithm: types.String("rsasha1", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Zone signing using RSA SHA512 key",
			input: dns.DNS{
				Metadata: types.NewTestMetadata(),
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: types.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: types.NewTestMetadata(),
							DefaultKeySpecs: dns.KeySpecs{
								Metadata: types.NewTestMetadata(),
								KeySigningKey: dns.Key{
									Metadata:  types.NewTestMetadata(),
									Algorithm: types.String("rsasha512", types.NewTestMetadata()),
								},
								ZoneSigningKey: dns.Key{
									Metadata:  types.NewTestMetadata(),
									Algorithm: types.String("rsasha512", types.NewTestMetadata()),
								},
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
			testState.Google.DNS = test.input
			results := CheckNoRsaSha1.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoRsaSha1.Rule().LongID() {
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
