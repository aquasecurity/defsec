package storage

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckBucketEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0066",
		Provider:    providers.GoogleProvider,
		Service:     "storage",
		ShortCode:   "bucket-encryption-customer-key",
		Summary:     "Cloud Storage buckets should be encrypted with a customer-managed key.",
		Impact:      "Using unmanaged keys does not allow for proper key management.",
		Resolution:  "Encrypt Cloud Storage buckets using customer-managed keys.",
		Explanation: `Using unmanaged keys makes rotation and general management difficult.`,
		Links: []string{
			"https://cloud.google.com/storage/docs/encryption/customer-managed-keys",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformBucketEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformBucketEncryptionCustomerKeyBadExamples,
			Links:               terraformBucketEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformBucketEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.Google.Storage.Buckets {
			if bucket.IsUnmanaged() {
				continue
			}
			if bucket.Encryption.DefaultKMSKeyName.IsEmpty() {
				results.Add(
					"Storage bucket encryption does not use a customer-managed key.",
					bucket.Encryption.DefaultKMSKeyName,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return
	},
)
