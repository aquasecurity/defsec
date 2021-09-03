package s3

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableBucketEncryption = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "s3",
		ShortCode:   "enable-bucket-encryption",
		Summary:     "Unencrypted S3 bucket.",
		Impact:      "The bucket objects could be read if compromised",
		Resolution:  "Configure bucket encryption",
		Explanation: `S3 Buckets should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific buckets.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
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
