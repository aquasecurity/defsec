package mssql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckAllThreatAlertsEnabled = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "mssql",
		ShortCode:   "all-threat-alerts-enabled",
		Summary:     "No threat detections are set",
		Impact:      "Disabling threat alerts means you are not getting the full benefit of server security protection",
		Resolution:  "Use all provided threat alerts",
		Explanation: `SQL Server can alert for security issues including SQL Injection, vulnerabilities, access anomalies and data exfiltration. Ensure none of these are disabled to benefit from the best protection`,
		Links: []string{ 
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled,
					
				)
			}
		}
		return
	},
)
