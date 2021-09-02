package rds

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnablePerformanceInsights = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "rds",
		ShortCode:   "enable-performance-insights",
		Summary:     "Encryption for RDS Performance Insights should be enabled.",
		Impact:      "Data can be read from the RDS Performance Insights if it is compromised",
		Resolution:  "Enable encryption for RDS clusters and instances",
		Explanation: `When enabling Performance Insights on an RDS cluster or RDS DB Instance, and encryption key should be provided.

The encryption key specified in ` + "`" + `performance_insights_kms_key_id` + "`" + ` references a KMS ARN`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm",
		},
		Severity: severity.High,
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
