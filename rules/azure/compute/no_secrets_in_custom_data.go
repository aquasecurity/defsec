package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoSecretsInCustomData = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "compute",
		ShortCode:   "no-secrets-in-custom-data",
		Summary:     "Ensure that no sensitive credentials are exposed in VM custom_data",
		Impact:      "Sensitive credentials in custom_data can be leaked",
		Resolution:  "Don't use sensitive credentials in the VM custom_data",
		Explanation: `When creating Azure Virtual Machines, custom_data is used to pass start up information into the EC2 instance. This custom_dat must not contain access key credentials.`,
		Links: []string{ 
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
