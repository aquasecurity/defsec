package msk

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "msk",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "A MSK cluster allows unencrypted data in transit.",
		Impact:      "Intercepted data can be read in transit",
		Resolution:  "Enable in transit encryption",
		Explanation: `Encryption should be forced for Kafka clusters, including for communication between nodes. This ensure sensitive data is kept private.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html",
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
