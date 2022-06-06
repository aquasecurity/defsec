package gke

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckMetadataEndpointsDisabled = rules.Register(
	scan.Rule{
		AVDID:      "AVD-GCP-0048",
		Provider:   providers.GoogleProvider,
		Service:    "gke",
		ShortCode:  "metadata-endpoints-disabled",
		Summary:    "Legacy metadata endpoints enabled.",
		Impact:     "Legacy metadata endpoints don't require metadata headers",
		Resolution: "Disable legacy metadata endpoints",
		Explanation: `The Compute Engine instance metadata server exposes legacy v0.1 and v1beta1 endpoints, which do not enforce metadata query headers. 

This is a feature in the v1 APIs that makes it more difficult for a potential attacker to retrieve instance metadata. 

Unless specifically required, we recommend you disable these legacy APIs.

When setting the <code>metadata</code> block, the default value for <code>disable-legacy-endpoints</code> is set to true, they should not be explicitly enabled.`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#protect_node_metadata_default_for_112",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformMetadataEndpointsDisabledGoodExamples,
			BadExamples:         terraformMetadataEndpointsDisabledBadExamples,
			Links:               terraformMetadataEndpointsDisabledLinks,
			RemediationMarkdown: terraformMetadataEndpointsDisabledRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.RemoveDefaultNodePool.IsTrue() {
				for _, pool := range cluster.NodePools {
					if pool.NodeConfig.EnableLegacyEndpoints.IsTrue() {
						results.Add(
							"Cluster has legacy metadata endpoints enabled.",
							pool.NodeConfig.EnableLegacyEndpoints,
						)
					}
				}
			} else if cluster.NodeConfig.EnableLegacyEndpoints.IsTrue() {
				results.Add(
					"Cluster has legacy metadata endpoints enabled.",
					cluster.NodeConfig.EnableLegacyEndpoints,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
