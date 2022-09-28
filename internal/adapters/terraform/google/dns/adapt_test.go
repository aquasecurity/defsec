package dns

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/dns"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   defsecTypes.NewTestMetadata(),
						Visibility: defsecTypes.String("public", defsecTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Enabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							DefaultKeySpecs: dns.KeySpecs{
								Metadata: defsecTypes.NewTestMetadata(),
								ZoneSigningKey: dns.Key{
									Metadata:  defsecTypes.NewTestMetadata(),
									Algorithm: defsecTypes.String("", defsecTypes.NewTestMetadata()),
								},
								KeySigningKey: dns.Key{
									Metadata:  defsecTypes.NewTestMetadata(),
									Algorithm: defsecTypes.String("rsasha1", defsecTypes.NewTestMetadata()),
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
				Metadata: defsecTypes.NewTestMetadata(),
				ZoneSigningKey: dns.Key{
					Metadata:  defsecTypes.NewTestMetadata(),
					Algorithm: defsecTypes.String("rsasha512", defsecTypes.NewTestMetadata()),
				},
				KeySigningKey: dns.Key{
					Metadata:  defsecTypes.NewTestMetadata(),
					Algorithm: defsecTypes.String("", defsecTypes.NewTestMetadata()),
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

	assert.Equal(t, 2, zone.Metadata.Range().GetStartLine())
	assert.Equal(t, 13, zone.Metadata.Range().GetEndLine())

	assert.Equal(t, 7, zone.DNSSec.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, zone.DNSSec.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, zone.DNSSec.DefaultKeySpecs.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, zone.DNSSec.DefaultKeySpecs.Metadata.Range().GetEndLine())

	assert.Equal(t, 9, zone.DNSSec.DefaultKeySpecs.KeySigningKey.Algorithm.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, zone.DNSSec.DefaultKeySpecs.KeySigningKey.Algorithm.GetMetadata().Range().GetEndLine())
}
