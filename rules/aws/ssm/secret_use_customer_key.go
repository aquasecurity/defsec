package ssm

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckSecretUseCustomerKey = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "ssm",
		ShortCode:   "secret-use-customer-key",
		Summary:     "Secrets Manager should use customer managed keys",
		Impact:      "Using AWS managed keys reduces the flexibility and control over the encryption key",
		Resolution:  "Use customer managed keys",
		Explanation: `Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt",
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
