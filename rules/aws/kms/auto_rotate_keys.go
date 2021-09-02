package kms

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckAutoRotateKeys = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "kms",
		ShortCode:   "auto-rotate-keys",
		Summary:     "A KMS key is not configured to auto-rotate.",
		Impact:      "Long life KMS keys increase the attack surface when compromised",
		Resolution:  "Configure KMS key to auto rotate",
		Explanation: `You should configure your KMS keys to auto rotate to maintain security and defend against compromise.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
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
