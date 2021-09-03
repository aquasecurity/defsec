package s3

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckSpecifyPublicAccessBlock = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "s3",
		ShortCode:   "specify-public-access-block",
		Summary:     "S3 buckets should each define an aws_s3_bucket_public_access_block",
		Impact:      "Public access policies may be applied to sensitive data buckets",
		Resolution:  "Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies",
		Explanation: `The "block public access" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central definition for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
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
