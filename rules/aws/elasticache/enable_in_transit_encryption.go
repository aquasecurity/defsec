package elasticache

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "elasticache",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "Elasticache Replication Group uses unencrypted traffic.",
		Impact:      "In transit data in the Replication Group could be read if intercepted",
		Resolution:  "Enable in transit encryption for replication group",
		Explanation: `Traffic flowing between Elasticache replication nodes should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html",
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
