package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPlaintextDiskKeys = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-plaintext-disk-keys",
		Summary:     "Disk encryption keys should not be provided in plaintext",
		Impact:      "Compromise of encryption keys",
		Resolution:  "Use managed keys or provide the raw key via a secrets manager ",
		Explanation: `Providing your encryption key in plaintext format means anyone with access to the source code also has access to the key.`,
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
