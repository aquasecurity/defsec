package keyvault

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnsureSecretExpiry = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "keyvault",
		ShortCode:   "ensure-secret-expiry",
		Summary:     "Key Vault Secret should have an expiration date set",
		Impact:      "Long life secrets increase the opportunity for compromise",
		Resolution:  "Set an expiry for secrets",
		Explanation: `Expiration Date is an optional Key Vault Secret behavior and is not set by default.

Set when the resource will be become inactive.`,
		Links: []string{ 
			"https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
		},
		Severity: severity.Low,
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
