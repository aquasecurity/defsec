package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptNetworks(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.Network
	}{
		{
			name: "defined",
			terraform: `
			resource "google_compute_subnetwork" "example" {
				name          = "test-subnetwork"
				network       = google_compute_network.example.id
				log_config {
				  aggregation_interval = "INTERVAL_10_MIN"
				  flow_sampling        = 0.5
				  metadata             = "INCLUDE_ALL_METADATA"
				}
			  }

			  resource "google_compute_network" "example" {
				name                    = "test-network"
				auto_create_subnetworks = false
			  }

			  resource "google_compute_firewall" "example" {
				name        = "my-firewall-rule"
				network = google_compute_network.example.name
				source_ranges = ["1.2.3.4/32"]
				allow {
				  protocol = "icmp"
				  ports     = ["80", "8080"]
				}
			  }
`,
			expected: []compute.Network{
				{
					Metadata: types.NewTestMetadata(),
					Firewall: &compute.Firewall{
						Metadata: types.NewTestMetadata(),
						Name:     types.String("my-firewall-rule", types.NewTestMetadata()),
						IngressRules: []compute.IngressRule{
							{
								Metadata: types.NewTestMetadata(),
								FirewallRule: compute.FirewallRule{
									Metadata: types.NewTestMetadata(),
									IsAllow:  types.Bool(true, types.NewTestMetadata()),
									Protocol: types.String("icmp", types.NewTestMetadata()),
									Enforced: types.Bool(true, types.NewTestMetadata()),
									Ports: []types.IntValue{
										types.Int(80, types.NewTestMetadata()),
										types.Int(8080, types.NewTestMetadata()),
									},
								},
								SourceRanges: []types.StringValue{
									types.String("1.2.3.4/32", types.NewTestMetadata()),
								},
							},
						},
					},
					Subnetworks: []compute.SubNetwork{
						{
							Metadata:       types.NewTestMetadata(),
							Name:           types.String("test-subnetwork", types.NewTestMetadata()),
							EnableFlowLogs: types.Bool(true, types.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_subnetwork" "example" {
				network       = google_compute_network.example.id
			  }

			  resource "google_compute_network" "example" {
			  }

			  resource "google_compute_firewall" "example" {
				network = google_compute_network.example.name
			}
`,
			expected: []compute.Network{
				{
					Metadata: types.NewTestMetadata(),
					Firewall: &compute.Firewall{
						Metadata: types.NewTestMetadata(),
						Name:     types.String("", types.NewTestMetadata()),
					},
					Subnetworks: []compute.SubNetwork{
						{
							Metadata:       types.NewTestMetadata(),
							Name:           types.String("", types.NewTestMetadata()),
							EnableFlowLogs: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptNetworks(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
