package ebs

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "ebs",
		ShortCode:   "encryption-customer-key",
		Summary:     "EBS volume encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your EBS volume. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links: []string{ 
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
