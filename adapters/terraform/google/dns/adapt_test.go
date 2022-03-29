package dns

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/providers/google/dns"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  dns.DNS
	}{
		{
			name: "basic",
			terraform: `
			resource "google_dns_managed_zone" "example" {
				name        = "example-zone"
				dns_name    = "example-${random_id.rnd.hex}.com."
				description = "Example DNS zone"
				labels = {
				  foo = "bar"
				}
				dnssec_config {
				  state = "on"
				  default_key_specs {
					  algorithm = "rsasha1"
					  key_type = "keySigning"
				  }
				}
			}
`,
			expected: dns.DNS{
				Metadata: types.NewTestMetadata(),
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: types.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Enabled: types.Bool(true, types.NewTestMetadata()),
							DefaultKeySpecs: dns.KeySpecs{
								Metadata: types.NewTestMetadata(),
								ZoneSigningKey: dns.Key{
									Metadata:  types.NewTestMetadata(),
									Algorithm: types.String("", types.NewTestMetadata()),
								},
								KeySigningKey: dns.Key{
									Metadata:  types.NewTestMetadata(),
									Algorithm: types.String("rsasha1", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptKeySpecs(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  dns.KeySpecs
	}{
		{
			name: "basic",
			terraform: `

			data "google_dns_keys" "foo_dns_keys" {
				managed_zone = google_dns_managed_zone.example.id
				zone_signing_keys {
					algorithm = "rsasha512"
				}
			}
`,
			expected: dns.KeySpecs{
				Metadata: types.NewTestMetadata(),
				ZoneSigningKey: dns.Key{
					Metadata:  types.NewTestMetadata(),
					Algorithm: types.String("rsasha512", types.NewTestMetadata()),
				},
				KeySigningKey: dns.Key{
					Metadata:  types.NewTestMetadata(),
					Algorithm: types.String("", types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptKeySpecs(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "google_dns_managed_zone" "example" {
		name        = "example-zone"
		dns_name    = "example-${random_id.rnd.hex}.com."

		dnssec_config {
		  state = "on"
		  default_key_specs {
			  algorithm = "rsasha1"
			  key_type = "keySigning"
		  }
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.ManagedZones, 1)
	zone := adapted.ManagedZones[0]

	assert.Equal(t, 2, zone.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, zone.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, zone.DNSSec.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, zone.DNSSec.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, zone.DNSSec.DefaultKeySpecs.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, zone.DNSSec.DefaultKeySpecs.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, zone.DNSSec.DefaultKeySpecs.KeySigningKey.Algorithm.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, zone.DNSSec.DefaultKeySpecs.KeySigningKey.Algorithm.GetMetadata().Range().GetEndLine())
}
