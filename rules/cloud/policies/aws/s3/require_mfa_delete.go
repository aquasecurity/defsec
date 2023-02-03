package s3

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckRequireMFADelete = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0170",
		Provider:  providers.AWSProvider,
		Service:   "s3",
		ShortCode: "require-mfa-delete",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"2.1.3"},
		},
		Summary:    "Buckets should have MFA deletion protection enabled.",
		Impact:     "Lessened protection against accidental/malicious deletion of data",
		Resolution: "Enable MFA deletion protection on the bucket",
		Explanation: `
Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete an object version, adding another layer of security in the event your security credentials are compromised or unauthorized access is obtained.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html",
		},
		Severity: severity.Low,
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRequireMFADeleteGoodExamples,
			BadExamples:         terraformRequireMFADeleteBadExamples,
			Links:               terraformRequireMFADeleteLinks,
			RemediationMarkdown: terraformRequireMFADeleteRemediationMarkdown,
		},
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.Versioning.MFADelete.IsFalse() {
				results.Add(
					"Bucket does not have MFA deletion protection enabled",
					bucket.Versioning.MFADelete,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
