package sql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableBackup = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "sql",
		ShortCode:   "enable-backup",
		Summary:     "Enable automated backups to recover from data-loss",
		Impact:      "No recovery of lost or corrupted data",
		Resolution:  "Enable automated backups",
		Explanation: `Automated backups are not enabled by default. Backups are an easy way to restore data in a corruption or data-loss scenario.`,
		Links: []string{ 
			"https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
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
