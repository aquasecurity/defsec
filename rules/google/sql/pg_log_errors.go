package sql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckPgLogErrors = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-errors",
		Summary:     "Ensure that Postgres errors are logged",
		Impact:      "Loss of error logging",
		Resolution:  "Set the minimum log severity to at least ERROR",
		Explanation: `Setting the minimum log severity too high will cause errors not to be logged`,
		Links: []string{ 
			"https://postgresqlco.nf/doc/en/param/log_min_messages/",
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-MESSAGES",
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
