package kms

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckRotateKmsKeys = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "kms",
		ShortCode:   "rotate-kms-keys",
		Summary:     "KMS keys should be rotated at least every 90 days",
		Impact:      "Exposure is greater if the same keys are used over a long period",
		Resolution:  "Set key rotation period to 90 days",
		Explanation: `Keys should be rotated on a regular basis to limit exposure if a given key should become compromised.`,
		Links: []string{ 
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
