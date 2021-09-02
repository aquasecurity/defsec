package keyvault

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnsureKeyExpiry = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "keyvault",
		ShortCode:   "ensure-key-expiry",
		Summary:     "Ensure that the expiration date is set on all keys",
		Impact:      "Long life keys increase the attack surface when compromised",
		Resolution:  "Set an expiration date on the vault key",
		Explanation: `Expiration Date is an optional Key Vault Key behavior and is not set by default.

Set when the resource will be become inactive.`,
		Links: []string{ 
			"https://docs.microsoft.com/en-us/powershell/module/az.keyvault/update-azkeyvaultkey?view=azps-5.8.0#example-1--modify-a-key-to-enable-it--and-set-the-expiration-date-and-tags",
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
