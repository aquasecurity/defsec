package container

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckConfiguredNetworkPolicy = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "container",
		ShortCode:   "configured-network-policy",
		Summary:     "Ensure AKS cluster has Network Policy configured",
		Impact:      "No network policy is protecting the AKS cluster",
		Resolution:  "Configure a network policy",
		Explanation: `The Kubernetes object type NetworkPolicy should be defined to have opportunity allow or block traffic to pods, as in a Kubernetes cluster configured with default settings, all pods can discover and communicate with each other without any restrictions.`,
		Links: []string{ 
			"https://kubernetes.io/docs/concepts/services-networking/network-policies",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled,
					
				)
			}
		}
		return
	},
)
