package storage

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnforceHttps = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "storage",
		ShortCode:   "enforce-https",
		Summary:     "Storage accounts should be configured to only accept transfers that are over secure connections",
		Impact:      "Insecure transfer of data into secure accounts could be read if intercepted",
		Resolution:  "Only allow secure connection for transferring data into storage accounts",
		Explanation: `You can configure your storage account to accept requests from secure connections only by setting the Secure transfer required property for the storage account. 

When you require secure transfer, any requests originating from an insecure connection are rejected. 

Microsoft recommends that you always require secure transfer for all of your storage accounts.`,
		Links: []string{ 
			"https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
		},
		Severity: severity.High,
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
