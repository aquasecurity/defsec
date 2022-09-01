package bigquery

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckDatasetEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0067",
		Provider:    providers.GoogleProvider,
		Service:     "bigquery",
		ShortCode:   "dataset-encryption-customer-key",
		Summary:     "BigQuery datasets should be configured to use a customer-managed encryption key",
		Impact:      "Using unmanaged keys does not allow for proper key management.",
		Resolution:  "Configure BigQuery datasets to use a customer-managed encryption key.",
		Explanation: `BigQuery datasets are encrypted by default using Google managed encryption keys. To increase control of the encryption and enable managing factors like key rotation, use a customer-managed key.`,
		Links: []string{
			"https://cloud.google.com/bigquery/docs/customer-managed-encryption",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformDatasetEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformDatasetEncryptionCustomerKeyBadExamples,
			Links:               terraformDatasetEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformDatasetEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, dataset := range s.Google.BigQuery.Datasets {
			if dataset.IsUnmanaged() {
				continue
			}
			if dataset.DefaultEncryptionConfiguration.KMSKeyName.IsEmpty() {
				results.Add(
					"Dataset is not configured to use a customer-managed encryption key.",
					dataset.DefaultEncryptionConfiguration.KMSKeyName,
				)
			} else {
				results.AddPassed(&dataset)
			}
		}
		return
	},
)
