package gke

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  gke.GKE
	}{
		{
			name: "separately defined pool",
			terraform: `
			resource "google_service_account" "default" {
				account_id   = "service-account-id"
				display_name = "Service Account"
			  }

			resource "google_container_cluster" "example" {
				name     = "my-gke-cluster"

				node_config {			  
					metadata = {
					  disable-legacy-endpoints = true
					}
				}

				pod_security_policy_config {
					enabled = "true"
				}

				enable_legacy_abac = "true"
				enable_shielded_nodes = "true"
			
				remove_default_node_pool = true
				initial_node_count       = 1
				monitoring_service = "monitoring.googleapis.com/kubernetes"
				logging_service = "logging.googleapis.com/kubernetes"

				master_auth {
					client_certificate_config {
					  issue_client_certificate = true
					}
				  }

				master_authorized_networks_config {
					cidr_blocks {
					  cidr_block = "10.10.128.0/24"
					  display_name = "internal"
					}
				  }

				resource_labels = {
				  "env" = "staging"
				}

				private_cluster_config {
					enable_private_nodes = true
				  }

				  network_policy {
					enabled = true
				  }

				  ip_allocation_policy {}

			  }
			  
			  resource "google_container_node_pool" "primary_preemptible_nodes" {
				cluster    = google_container_cluster.example.name
				node_count = 1
			  
				node_config {			  
				  service_account = google_service_account.default.email
				  metadata = {
					disable-legacy-endpoints = true
				}
				  image_type = "COS_CONTAINERD"
				  workload_metadata_config {
					mode = "GCE_METADATA"
				  }
				}
				management {
					auto_repair = true
					auto_upgrade = true
				  }
			  }
`,
			expected: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types2.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  types2.NewTestMetadata(),
							ImageType: types2.String("COS_CONTAINERD", types2.NewTestMetadata()),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     types2.NewTestMetadata(),
								NodeMetadata: types2.String("GCE_METADATA", types2.NewTestMetadata()),
							},
							ServiceAccount:        types2.String("", types2.NewTestMetadata()),
							EnableLegacyEndpoints: types2.Bool(false, types2.NewTestMetadata()),
						},
						NodePools: []gke.NodePool{
							{
								Metadata: types2.NewTestMetadata(),
								Management: gke.Management{
									Metadata:          types2.NewTestMetadata(),
									EnableAutoRepair:  types2.Bool(true, types2.NewTestMetadata()),
									EnableAutoUpgrade: types2.Bool(true, types2.NewTestMetadata()),
								},
								NodeConfig: gke.NodeConfig{
									Metadata:  types2.NewTestMetadata(),
									ImageType: types2.String("COS_CONTAINERD", types2.NewTestMetadata()),
									WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
										Metadata:     types2.NewTestMetadata(),
										NodeMetadata: types2.String("GCE_METADATA", types2.NewTestMetadata()),
									},
									ServiceAccount:        types2.String("", types2.NewTestMetadata()),
									EnableLegacyEndpoints: types2.Bool(false, types2.NewTestMetadata()),
								},
							},
						},
						IPAllocationPolicy: gke.IPAllocationPolicy{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(true, types2.NewTestMetadata()),
						},
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(true, types2.NewTestMetadata()),
							CIDRs: []types2.StringValue{
								types2.String("10.10.128.0/24", types2.NewTestMetadata()),
							},
						},
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(true, types2.NewTestMetadata()),
						},
						PrivateCluster: gke.PrivateCluster{
							Metadata:           types2.NewTestMetadata(),
							EnablePrivateNodes: types2.Bool(true, types2.NewTestMetadata()),
						},
						LoggingService:    types2.String("logging.googleapis.com/kubernetes", types2.NewTestMetadata()),
						MonitoringService: types2.String("monitoring.googleapis.com/kubernetes", types2.NewTestMetadata()),
						PodSecurityPolicy: gke.PodSecurityPolicy{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(true, types2.NewTestMetadata()),
						},
						MasterAuth: gke.MasterAuth{
							Metadata: types2.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         types2.NewTestMetadata(),
								IssueCertificate: types2.Bool(true, types2.NewTestMetadata()),
							},
							Username: types2.String("", types2.NewTestMetadata()),
							Password: types2.String("", types2.NewTestMetadata()),
						},
						EnableShieldedNodes: types2.Bool(true, types2.NewTestMetadata()),
						EnableLegacyABAC:    types2.Bool(true, types2.NewTestMetadata()),
						ResourceLabels: types2.Map(map[string]string{
							"env": "staging",
						}, types2.NewTestMetadata()),
						RemoveDefaultNodePool: types2.Bool(true, types2.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "default node pool",
			terraform: `

			resource "google_container_cluster" "example" {
				node_config {			  
					service_account = "service-account"
					metadata = {
					  disable-legacy-endpoints = true
				  }
					image_type = "COS"
					workload_metadata_config {
					  mode = "GCE_METADATA"
					}
				  }
			  }	
`,
			expected: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: types2.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  types2.NewTestMetadata(),
							ImageType: types2.String("COS", types2.NewTestMetadata()),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     types2.NewTestMetadata(),
								NodeMetadata: types2.String("GCE_METADATA", types2.NewTestMetadata()),
							},
							ServiceAccount:        types2.String("service-account", types2.NewTestMetadata()),
							EnableLegacyEndpoints: types2.Bool(false, types2.NewTestMetadata()),
						},

						IPAllocationPolicy: gke.IPAllocationPolicy{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(false, types2.NewTestMetadata()),
						},
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(false, types2.NewTestMetadata()),
							CIDRs:    []types2.StringValue{},
						},
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(false, types2.NewTestMetadata()),
						},
						PrivateCluster: gke.PrivateCluster{
							Metadata:           types2.NewTestMetadata(),
							EnablePrivateNodes: types2.Bool(false, types2.NewTestMetadata()),
						},
						LoggingService:    types2.String("logging.googleapis.com/kubernetes", types2.NewTestMetadata()),
						MonitoringService: types2.String("monitoring.googleapis.com/kubernetes", types2.NewTestMetadata()),
						PodSecurityPolicy: gke.PodSecurityPolicy{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(false, types2.NewTestMetadata()),
						},
						MasterAuth: gke.MasterAuth{
							Metadata: types2.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         types2.NewTestMetadata(),
								IssueCertificate: types2.Bool(false, types2.NewTestMetadata()),
							},
							Username: types2.String("", types2.NewTestMetadata()),
							Password: types2.String("", types2.NewTestMetadata()),
						},
						EnableShieldedNodes:   types2.Bool(true, types2.NewTestMetadata()),
						EnableLegacyABAC:      types2.Bool(false, types2.NewTestMetadata()),
						ResourceLabels:        types2.Map(map[string]string{}, types2.NewTestMetadata()),
						RemoveDefaultNodePool: types2.Bool(false, types2.NewTestMetadata()),
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

func TestLines(t *testing.T) {
	src := `
	resource "google_container_cluster" "example" {

		node_config {
			metadata = {
				disable-legacy-endpoints = true
			}
		}
		pod_security_policy_config {
			enabled = "true"
		}

		enable_legacy_abac = "true"
		enable_shielded_nodes = "true"
	
		remove_default_node_pool = true
		monitoring_service = "monitoring.googleapis.com/kubernetes"
		logging_service = "logging.googleapis.com/kubernetes"

		master_auth {
			client_certificate_config {
			  issue_client_certificate = true
			}
		}

		master_authorized_networks_config {
			cidr_blocks {
			  cidr_block = "10.10.128.0/24"
			}
		  }

		resource_labels = {
		  "env" = "staging"
		}

		private_cluster_config {
			enable_private_nodes = true
		}

		network_policy {
			enabled = true
		}
		ip_allocation_policy {}
	  }
	  
	  resource "google_container_node_pool" "primary_preemptible_nodes" {
		cluster    = google_container_cluster.example.name
	  
		node_config {
			metadata = {
				disable-legacy-endpoints = true
			}
			service_account = google_service_account.default.email
			image_type = "COS_CONTAINERD"

			workload_metadata_config {
				mode = "GCE_METADATA"
			}
		}
		management {
			auto_repair = true
			auto_upgrade = true
		}
	  }
	`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	cluster := adapted.Clusters[0]
	nodePool := cluster.NodePools[0]

	assert.Equal(t, 2, cluster.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 44, cluster.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 49, cluster.NodeConfig.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 59, cluster.NodeConfig.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 50, cluster.NodeConfig.EnableLegacyEndpoints.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 52, cluster.NodeConfig.EnableLegacyEndpoints.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, cluster.PodSecurityPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, cluster.PodSecurityPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.PodSecurityPolicy.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.PodSecurityPolicy.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, cluster.EnableLegacyABAC.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, cluster.EnableLegacyABAC.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, cluster.EnableShieldedNodes.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, cluster.EnableShieldedNodes.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, cluster.RemoveDefaultNodePool.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, cluster.RemoveDefaultNodePool.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, cluster.MonitoringService.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, cluster.MonitoringService.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, cluster.LoggingService.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, cluster.LoggingService.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 20, cluster.MasterAuth.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, cluster.MasterAuth.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, cluster.MasterAuth.ClientCertificate.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, cluster.MasterAuth.ClientCertificate.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, cluster.MasterAuth.ClientCertificate.IssueCertificate.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, cluster.MasterAuth.ClientCertificate.IssueCertificate.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, cluster.MasterAuthorizedNetworks.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 30, cluster.MasterAuthorizedNetworks.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 28, cluster.MasterAuthorizedNetworks.CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 28, cluster.MasterAuthorizedNetworks.CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 32, cluster.ResourceLabels.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, cluster.ResourceLabels.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 36, cluster.PrivateCluster.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 38, cluster.PrivateCluster.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 37, cluster.PrivateCluster.EnablePrivateNodes.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 37, cluster.PrivateCluster.EnablePrivateNodes.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 40, cluster.NetworkPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 42, cluster.NetworkPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 41, cluster.NetworkPolicy.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 41, cluster.NetworkPolicy.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 43, cluster.IPAllocationPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 43, cluster.IPAllocationPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 46, nodePool.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 64, nodePool.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 49, nodePool.NodeConfig.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 59, nodePool.NodeConfig.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 53, nodePool.NodeConfig.ServiceAccount.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 53, nodePool.NodeConfig.ServiceAccount.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 54, nodePool.NodeConfig.ImageType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 54, nodePool.NodeConfig.ImageType.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 56, nodePool.NodeConfig.WorkloadMetadataConfig.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 58, nodePool.NodeConfig.WorkloadMetadataConfig.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 57, nodePool.NodeConfig.WorkloadMetadataConfig.NodeMetadata.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 57, nodePool.NodeConfig.WorkloadMetadataConfig.NodeMetadata.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 60, nodePool.Management.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 63, nodePool.Management.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 61, nodePool.Management.EnableAutoRepair.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 61, nodePool.Management.EnableAutoRepair.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 62, nodePool.Management.EnableAutoUpgrade.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 62, nodePool.Management.EnableAutoUpgrade.GetMetadata().Range().GetEndLine())

}
