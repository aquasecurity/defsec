package container

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckLogging = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "container",
		ShortCode:   "logging",
		Summary:     "Ensure AKS logging to Azure Monitoring is Configured",
		Impact:      "Logging provides valuable information about access and usage",
		Resolution:  "Enable logging for AKS",
		Explanation: `Ensure AKS logging to Azure Monitoring is configured for containers to monitor the performance of workloads.`,
		Links: []string{ 
			"https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-onboard",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled.Metadata(),
					x.Encryption.Enabled.Value(),
				)
			}
		}
		return
	},
)
