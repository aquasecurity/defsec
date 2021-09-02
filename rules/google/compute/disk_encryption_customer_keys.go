package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckDiskEncryptionCustomerKeys = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "disk-encryption-customer-keys",
		Summary:     "Encrypted compute disk with unmanaged keys.",
		Impact:      "Encryption of disk using unmanaged keys.",
		Resolution:  "Enable encryption using a customer-managed key.",
		Explanation: `By default, Compute Engine encrypts all data at rest. Compute Engine handles and manages this encryption for you without any additional actions on your part.

If the <code>disk_encryption_key</code> block is included in the resource declaration then it *must* include a <code>raw_key</code> or <code>kms_key_self_link</code>.`,
		Links: []string{ 
			"https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
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
