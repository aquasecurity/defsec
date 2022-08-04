package cloudtrail

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var checkNoPublicLogAccess = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0161",
		Provider:  providers.AWSProvider,
		Service:   "cloudtrail",
		ShortCode: "no-public-log-access",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"2.3"},
			framework.CIS_AWS_1_4: {"3.3"},
		},
		Summary:    "The S3 Bucket backing Cloudtrail should be private",
		Impact:     "CloudTrail logs will be publicly exposed, potentially containing sensitive information",
		Resolution: "Restrict public access to the S3 bucket",
		Explanation: `
CloudTrail logs a record of every API call made in your account. These log files are stored in an S3 bucket. CIS recommends that the S3 bucket policy, or access control list (ACL), applied to the S3 bucket that CloudTrail logs to prevents public access to the CloudTrail logs. Allowing public access to CloudTrail log content might aid an adversary in identifying weaknesses in the affected account's use or configuration.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access-bucket.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicLogAccessGoodExamples,
			BadExamples:         terraformNoPublicLogAccessBadExamples,
			Links:               terraformNoPublicLogAccessLinks,
			RemediationMarkdown: terraformNoPublicLogAccessRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicLogAccessGoodExamples,
			BadExamples:         cloudFormationNoPublicLogAccessBadExamples,
			Links:               cloudFormationNoPublicLogAccessLinks,
			RemediationMarkdown: cloudFormationNoPublicLogAccessRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, trail := range s.AWS.CloudTrail.Trails {
			if trail.BucketName.IsNotEmpty() {
				for _, bucket := range s.AWS.S3.Buckets {
					if bucket.Name.EqualTo(trail.BucketName.Value()) {
						if bucket.HasPublicExposureACL() {
							results.Add("Trail S3 bucket is publicly exposed", &bucket)
						} else {
							results.AddPassed(&bucket)
						}
					}
				}
			}
		}
		return
	},
)
