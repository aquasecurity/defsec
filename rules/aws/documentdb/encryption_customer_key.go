package documentdb

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "documentdb",
		ShortCode:   "encryption-customer-key",
		Summary:     "DocumentDB encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your DocumentDB underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links:       []string{},
		Severity:    severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.DocumentDB.Clusters {
			if cluster.IsManaged() && cluster.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster encryption does not use a customer-managed KMS key.",
					cluster.KMSKeyID.Metadata(),
					cluster.KMSKeyID.Value(),
				)
			}
			for _, instance := range cluster.Instances {
				if !instance.IsManaged() {
					continue
				}
				if instance.KMSKeyID.IsEmpty() {
					results.Add(
						"Instance encryption does not use a customer-managed KMS key.",
						instance.KMSKeyID.Metadata(),
						instance.KMSKeyID.Value(),
					)
				}

			}
		}
		return
	},
)
