package cloudfront

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableLogging = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "cloudfront",
		ShortCode:   "enable-logging",
		Summary:     "Cloudfront distribution should have Access Logging configured",
		Impact:      "Logging provides vital information about access and usage",
		Resolution:  "Enable logging for CloudFront distributions",
		Explanation: `You should configure CloudFront Access Logging to create log files that contain detailed information about every user request that CloudFront receives`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
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
