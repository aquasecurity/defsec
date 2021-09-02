package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckVmDiskEncryptionCustomerKey = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "vm-disk-encryption-customer-key",
		Summary:     "VM disks should be encrypted with Customer Supplied Encryption Keys",
		Impact:      "Using unmanaged keys does not allow for proper management",
		Resolution:  "Use managed keys ",
		Explanation: `Using unmanaged keys makes rotation and general management difficult.`,
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
