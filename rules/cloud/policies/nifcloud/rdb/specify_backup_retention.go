package rdb

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckBackupRetentionSpecified = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0009",
		Provider:    providers.NifcloudProvider,
		Service:     "rdb",
		ShortCode:   "specify-backup-retention",
		Summary:     "RDB instance should have backup retention longer than 1 day",
		Impact:      "Potential loss of data and short opportunity for recovery",
		Resolution:  "Explicitly set the retention period to greater than the default",
		Explanation: `Backup retention periods should be set to a period that is a balance on cost and limiting risk.`,
		Links: []string{
			"https://pfs.nifcloud.com/spec/rdb/snapshot_backup.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformSpecifyBackupRetentionGoodExamples,
			BadExamples:         terraformSpecifyBackupRetentionBadExamples,
			Links:               terraformSpecifyBackupRetentionLinks,
			RemediationMarkdown: terraformSpecifyBackupRetentionRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Nifcloud.RDB.DBInstances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.BackupRetentionPeriodDays.LessThan(2) {
				results.Add(
					"Instance has very low backup retention period.",
					instance.BackupRetentionPeriodDays,
				)
			} else {
				results.AddPassed(&instance)
			}
		}

		return
	},
)
