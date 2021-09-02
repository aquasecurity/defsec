package dynamodb

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableRecovery = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "dynamodb",
		ShortCode:   "enable-recovery",
		Summary:     "Point in time recovery should be enabled to protect DynamoDB table",
		Impact:      "Accidental or malicious writes and deletes can't be rolled back",
		Resolution:  "Enable point in time recovery",
		Explanation: `DynamoDB tables should be protected against accidentally or malicious write/delete actions by ensuring that there is adequate protection.

By enabling point-in-time-recovery you can restore to a known point in the event of loss of data.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
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
