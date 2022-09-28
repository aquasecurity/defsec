package bigquery

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckTableEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0068",
		Provider:    providers.GoogleProvider,
		Service:     "bigquery",
		ShortCode:   "table-encryption-customer-key",
		Summary:     "BigQuery tables should be configured to use a customer-managed encryption key",
		Impact:      "Using unmanaged keys does not allow for proper key management.",
		Resolution:  "Configure BigQuery tables to use a customer-managed encryption key.",
		Explanation: `BigQuery tables are encrypted by default using Google managed encryption keys. To increase control of the encryption and enable managing factors like key rotation, use a customer-managed key. This alert can often be ignored if the dataset is configured with a default customer-managed encryption key prior to the table creation.`,
		Links: []string{
			"https://cloud.google.com/bigquery/docs/customer-managed-encryption",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformTableEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformTableEncryptionCustomerKeyBadExamples,
			Links:               terraformTableEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformTableEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, table := range s.Google.BigQuery.Tables {
			if table.IsUnmanaged() {
				continue
			}
			if table.EncryptionConfiguration.KMSKeyName.IsEmpty() {
				results.Add(
					"Table is not configured to use a customer-managed encryption key.",
					table.EncryptionConfiguration.KMSKeyName,
				)
			} else {
				results.AddPassed(&table)
			}
		}
		return
	},
)
