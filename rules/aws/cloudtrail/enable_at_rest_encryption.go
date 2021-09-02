package cloudtrail

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "cloudtrail",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Cloudtrail should be encrypted at rest to secure access to sensitive trail data",
		Impact:      "Data can be freely read if compromised",
		Resolution:  "Enable encryption at rest",
		Explanation: `Cloudtrail logs should be encrypted at rest to secure the sensitive data. Cloudtrail logs record all activity that occurs in the the account through API calls and would be one of the first places to look when reacting to a breach.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
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
