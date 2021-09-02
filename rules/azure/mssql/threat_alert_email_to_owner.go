package mssql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckThreatAlertEmailToOwner = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "mssql",
		ShortCode:   "threat-alert-email-to-owner",
		Summary:     "Security threat alerts go to subcription owners and co-administrators",
		Impact:      "Administrators and subscription owners may have a delayed response",
		Resolution:  "Enable email to subscription owners",
		Explanation: `Subscription owners should be notified when there are security alerts. By ensuring the administrators of the account have been notified they can quickly assist in any required remediation`,
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
