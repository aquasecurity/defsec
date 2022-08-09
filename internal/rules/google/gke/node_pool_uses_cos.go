package gke

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
)

var CheckNodePoolUsesCos = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0054",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "node-pool-uses-cos",
		Summary:     "Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image",
		Impact:      "COS is the recommended OS image to use on cluster nodes",
		Resolution:  "Use the COS image type",
		Explanation: `GKE supports several OS image types but COS is the recommended OS image to use on cluster nodes for enhanced security`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNodePoolUsesCosGoodExamples,
			BadExamples:         terraformNodePoolUsesCosBadExamples,
			Links:               terraformNodePoolUsesCosLinks,
			RemediationMarkdown: terraformNodePoolUsesCosRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsManaged() {
				if cluster.NodeConfig.ImageType.NotEqualTo("") && cluster.NodeConfig.ImageType.NotEqualTo("COS_CONTAINERD", types.IgnoreCase) && cluster.NodeConfig.ImageType.NotEqualTo("COS", types.IgnoreCase) {
					results.Add(
						"Cluster is not configuring node pools to use the COS containerd image type by default.",
						cluster.NodeConfig.ImageType,
					)
				} else {
					results.AddPassed(&cluster)
				}
			}
			for _, pool := range cluster.NodePools {
				if pool.NodeConfig.ImageType.NotEqualTo("COS_CONTAINERD", types.IgnoreCase) && pool.NodeConfig.ImageType.NotEqualTo("COS", types.IgnoreCase) {
					results.Add(
						"Node pool is not using the COS containerd image type.",
						pool.NodeConfig.ImageType,
					)
				} else {
					results.AddPassed(&pool)
				}

			}
		}
		return
	},
)
