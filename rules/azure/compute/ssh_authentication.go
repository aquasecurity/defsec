package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckSshAuthentication = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "compute",
		ShortCode:   "ssh-authentication",
		Summary:     "Password authentication in use instead of SSH keys.",
		Impact:      "Passwords are potentially easier to compromise than SSH Keys",
		Resolution:  "Use SSH keys for authentication",
		Explanation: `Access to instances should be authenticated using SSH keys. Removing the option of password authentication enforces more secure methods while removing the risks inherent with passwords.`,
		Links: []string{ 
			"https://docs.microsoft.com/en-us/azure/virtual-machines/linux/create-ssh-keys-detailed",
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
