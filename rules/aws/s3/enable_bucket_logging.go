package s3

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableBucketLogging = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "s3",
		ShortCode:   "enable-bucket-logging",
		Summary:     "S3 Bucket does not have logging enabled.",
		Impact:      "There is no way to determine the access to this bucket",
		Resolution:  "Add a logging block to the resource to enable access logging",
		Explanation: `Buckets should have logging enabled so that access can be audited.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html",
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
