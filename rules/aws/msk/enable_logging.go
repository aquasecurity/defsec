package msk

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableLogging = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "msk",
		ShortCode:   "enable-logging",
		Summary:     "Ensure MSK Cluster logging is enabled",
		Impact:      "Without logging it is difficult to trace issues",
		Resolution:  "Enable logging",
		Explanation: `Managed streaming for Kafka can log to Cloud Watch, Kinesis Firehose and S3, at least one of these locations should be logged to`,
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
