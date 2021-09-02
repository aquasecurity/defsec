package mssql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckThreatAlertEmailSet = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "mssql",
		ShortCode:   "threat-alert-email-set",
		Summary:     "At least one email address is set for threat alerts",
		Impact:      "Nobody will be prompty alerted in the case of a threat being detected",
		Resolution:  "Provide at least one email address for threat alerts",
		Explanation: `SQL Server sends alerts for threat detection via email, if there are no email addresses set then mitigation will be delayed.`,
		Links: []string{ 
		},
		Severity: severity.Medium,
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
