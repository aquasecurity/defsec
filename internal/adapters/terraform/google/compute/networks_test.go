package compute

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
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
					Metadata: types2.NewTestMetadata(),
					Firewall: &compute.Firewall{
						Metadata: types2.NewTestMetadata(),
						Name:     types2.String("my-firewall-rule", types2.NewTestMetadata()),
						IngressRules: []compute.IngressRule{
							{
								Metadata: types2.NewTestMetadata(),
								FirewallRule: compute.FirewallRule{
									Metadata: types2.NewTestMetadata(),
									IsAllow:  types2.Bool(true, types2.NewTestMetadata()),
									Protocol: types2.String("icmp", types2.NewTestMetadata()),
									Enforced: types2.Bool(true, types2.NewTestMetadata()),
									Ports: []types2.IntValue{
										types2.Int(80, types2.NewTestMetadata()),
										types2.Int(8080, types2.NewTestMetadata()),
									},
								},
								SourceRanges: []types2.StringValue{
									types2.String("1.2.3.4/32", types2.NewTestMetadata()),
								},
							},
						},
					},
					Subnetworks: []compute.SubNetwork{
						{
							Metadata:       types2.NewTestMetadata(),
							Name:           types2.String("test-subnetwork", types2.NewTestMetadata()),
							EnableFlowLogs: types2.Bool(true, types2.NewTestMetadata()),
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
					Metadata: types2.NewTestMetadata(),
					Firewall: &compute.Firewall{
						Metadata: types2.NewTestMetadata(),
						Name:     types2.String("", types2.NewTestMetadata()),
					},
					Subnetworks: []compute.SubNetwork{
						{
							Metadata:       types2.NewTestMetadata(),
							Name:           types2.String("", types2.NewTestMetadata()),
							EnableFlowLogs: types2.Bool(false, types2.NewTestMetadata()),
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
