package datafactory

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccess = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "datafactory",
		ShortCode:   "no-public-access",
		Summary:     "Data Factory should have public access disabled, the default is enabled.",
		Impact:      "Data factory is publicly accessible",
		Resolution:  "Set public access to disabled for Data Factory",
		Explanation: `Data Factory has public access set to true by default.

Disabling public network access is applicable only to the self-hosted integration runtime, not to Azure Integration Runtime and SQL Server Integration Services (SSIS) Integration Runtime.`,
		Links: []string{ 
			"https://docs.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations#hybrid-scenarios",
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
