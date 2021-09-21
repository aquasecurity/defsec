package sql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckPgLogCheckpoints = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-checkpoints",
		Summary:     "Ensure that logging of checkpoints is enabled.",
		Impact:      "Insufficient diagnostic data.",
		Resolution:  "Enable checkpoints logging.",
		Explanation: `Logging checkpoints provides useful diagnostic data, which can identify performance issues in an application and potential DoS vectors.`,
		Links: []string{ 
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-CHECKPOINTS",
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
