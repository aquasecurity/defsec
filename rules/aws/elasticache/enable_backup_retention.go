package elasticache

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableBackupRetention = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "elasticache",
		ShortCode:   "enable-backup-retention",
		Summary:     "Redis cluster should have backup retention turned on",
		Impact:      "Without backups of the redis cluster recovery is made difficult",
		Resolution:  "Configure snapshot retention for redis cluster",
		Explanation: `Redis clusters should have a snapshot retention time to ensure that they are backed up and can be restored if required.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html",
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
