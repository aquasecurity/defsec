package container

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckLimitAuthorizedIps = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "container",
		ShortCode:   "limit-authorized-ips",
		Summary:     "Ensure AKS has an API Server Authorized IP Ranges enabled",
		Impact:      "Any IP can interact with the API server",
		Resolution:  "Limit the access to the API server to a limited IP range",
		Explanation: `The API server is the central way to interact with and manage a cluster. To improve cluster security and minimize attacks, the API server should only be accessible from a limited set of IP address ranges.`,
		Links: []string{ 
			"https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges",
		},
		Severity: severity.Critical,
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
