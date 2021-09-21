package sql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckPgLogDisconnections = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-disconnections",
		Summary:     "Ensure that logging of disconnections is enabled.",
		Impact:      "Insufficient diagnostic data.",
		Resolution:  "Enable disconnection logging.",
		Explanation: `Logging disconnections provides useful diagnostic data such as session length, which can identify performance issues in an application and potential DoS vectors.`,
		Links: []string{ 
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-DISCONNECTIONS",
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
